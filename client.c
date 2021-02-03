#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <sodium.h>

#include "aead.h"
#include "client.h"
#include "config.h"
#include "crypto.h"
#include "logger.h"
#include "socks.h"
#include "tcp.h"

struct client_context* alloc_client_context() {
    struct client_context* context =
        (struct client_context*)calloc(1, sizeof(struct client_context));
    if (context == NULL) {
        LOG_EXIT("Cannot create client_context.");
    }

    context->en_cipher = alloc_cipher(AEAD_CHACHA20_POLY1305, get_config(PASSWORD));
    context->stage = 1;

    return context;
}

void free_client_context(struct client_context* ctx) {
    free_cipher(ctx->en_cipher);
    free(ctx);
}

void client_decrypt_read(struct evbuffer* source, struct evbuffer* destination,
                         struct cipher* de_cipher) {
    // [salt]([encrypted payload length][length tag][encrypted payload][payload tag])...

    static unsigned char zero[MAX_SALT_LENGTH];

    // read [salt]
    if (memcmp(de_cipher->salt, zero, de_cipher->salt_size) == 0) {
        size_t data_size = evbuffer_get_length(source);
        if (data_size < de_cipher->salt_size) {
            return;
        }

        evbuffer_remove(source, de_cipher->salt, de_cipher->salt_size);

        if (data_size == de_cipher->salt_size) {
            return;
        }
    }

    // read ([encrypted payload length][length tag][encrypted payload][payload tag])...
    for (;;) {
        unsigned char* ciphertext = evbuffer_pullup(source, -1);
        static unsigned char plaintext[MAX_PAYLOAD_LENGTH];
        memset(plaintext, 0, sizeof plaintext);

        size_t data_len = evbuffer_get_length(source);
        int plaintext_len = aead_decrypt(de_cipher, ciphertext, data_len, plaintext);
        int ciphertext_len = 2 + 2 * de_cipher->tag_size + plaintext_len;

        if (plaintext_len >= 0) {
            evbuffer_drain(source, ciphertext_len);
            evbuffer_add(destination, plaintext, plaintext_len);

            if (data_len == ciphertext_len) {
                break;
            }

        } else if (plaintext_len == -2) {
            return;
        } else {
            LOG_WARN("Unexpected program execution.");
            break;
        }
    }
}

void client_encrypt_write(struct evbuffer* source, struct evbuffer* destination,
                          unsigned char* tgt_addr, struct cipher* en_cipher) {
    // [salt][target address][payload]
    // [salt]([encrypted payload length][length tag][encrypted payload][payload tag])...

    // [encrypted target address] is part of the [encrypted payload]

    static unsigned char zero[MAX_SALT_LENGTH];
    int need_send_addr = 0;

    // send [salt]
    if (memcmp(en_cipher->salt, zero, en_cipher->salt_size) == 0) {
        randombytes_buf(en_cipher->salt, en_cipher->salt_size);
        evbuffer_add(destination, en_cipher->salt, en_cipher->salt_size);

        need_send_addr = 1;
    }

    static unsigned char plaintext[MAX_PAYLOAD_LENGTH];
    memset(plaintext, 0, sizeof plaintext);

    // send ([encrypted payload length][length tag][encrypted payload][payload tag])...
    while (evbuffer_get_length(source) != 0) {
        size_t addr_len = 0;
        if (need_send_addr) {
            addr_len = read_tgt_addr(tgt_addr, plaintext);
            need_send_addr = 0;
        }

        size_t payload_len =
            evbuffer_remove(source, plaintext + addr_len, MAX_PAYLOAD_LENGTH - addr_len);
        size_t plaintext_len = addr_len + payload_len;
        size_t ciphertext_len = 2 + plaintext_len + 2 * en_cipher->tag_size;

        static unsigned char ciphertext[2 + 2 * MAX_TAG_LENGTH + MAX_PAYLOAD_LENGTH];
        memset(ciphertext, 0, sizeof ciphertext);

        aead_encrypt(en_cipher, plaintext, plaintext_len, ciphertext);
        evbuffer_add(destination, ciphertext, ciphertext_len);
    }
}

void client_read_cb(struct bufferevent* bev, void* arg) {
    struct client_context* ctx = (struct client_context*)arg;

    switch (ctx->stage) {
    case 0:
        // proxy server
        {
            struct evbuffer* in = bufferevent_get_input(bev);
            struct evbuffer* out = bufferevent_get_output(ctx->out_bev);

            client_encrypt_write(in, out, ctx->tgt_addr, ctx->en_cipher);
        }
        break;
    case 1:
        // a negotiation for the authentication method to be used
        stage1(bev, ctx);
        break;
    case 2:
        // request details from client
        stage2(bev, ctx);
        break;
    default:
        break;
    }
}

void client_write_cb(struct bufferevent* bev, void* arg) {
    struct client_context* ctx = (struct client_context*)arg;
    if (ctx->stage < 0) {
        if (ctx->out_bev != NULL) {
            bufferevent_free(ctx->out_bev);
        }
        bufferevent_free(bev);
        free_client_context(ctx);
    }
}

void client_event_cb(struct bufferevent* bev, short events, void* arg) {
    if (events & BEV_EVENT_ERROR) {
        LOG_WARN("Error from client socket - %s",
                 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        struct client_context* ctx = (struct client_context*)arg;

        if (ctx->out_bev != NULL) {
            bufferevent_free(ctx->out_bev);
        }
        bufferevent_free(bev);
        free_client_context(ctx);
    }
}

void client_accept_cb(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* addr,
                      int socklen, void* arg) {
    // processing incoming connect
    struct client_context* ctx = alloc_client_context();
    struct event_base* base = evconnlistener_get_base(listener);
    struct bufferevent* bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL) {
        LOG_EXIT("Cannot create bufferevent.");
    }

    bufferevent_setcb(bev, client_read_cb, client_write_cb, client_event_cb, ctx);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

void client_accept_error_cb(struct evconnlistener* listener, void* arg) {
    int err = EVUTIL_SOCKET_ERROR();
    LOG_EXIT("Got an error %d (%s) on the listener. "
             "Shutting down.",
             err, evutil_socket_error_to_string(err));
}
