#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <sodium.h>

#include "aead.h"
#include "config.h"
#include "crypto.h"
#include "logger.h"
#include "proxy.h"
#include "server.h"
#include "socks.h"

extern struct evdns_base* dns_base;

struct server_context* alloc_server_context() {
    struct server_context* context =
        (struct server_context*)calloc(1, sizeof(struct server_context));
    if (context == NULL) {
        LOG_EXIT("Cannot create server_context.");
    }

    context->de_cipher = alloc_cipher(AEAD_CHACHA20_POLY1305, get_config(PASSWORD));

    return context;
}

void free_server_context(struct server_context* ctx) {
    free_cipher(ctx->de_cipher);
    free(ctx);
}

void server_decrypt_read(struct bufferevent* bev, struct server_context* ctx) {
    // [salt]([encrypted payload length][length tag][encrypted payload][payload tag])...
    struct evbuffer* source = bufferevent_get_input(bev);
    struct cipher* de_cipher = ctx->de_cipher;

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
    while (evbuffer_get_length(source) != 0) {
        unsigned char* ciphertext = evbuffer_pullup(source, -1);
        static unsigned char plaintext[MAX_PAYLOAD_LENGTH];
        memset(plaintext, 0, sizeof plaintext);

        size_t data_len = evbuffer_get_length(source);

        int plaintext_len = aead_decrypt(de_cipher, ciphertext, data_len, plaintext);
        if (plaintext_len == -2) {
            return;
        } else if (plaintext_len == -1) {
            if (ctx->out_bev != NULL) {
                struct server_proxy_context* proxy_ctx;
                bufferevent_getcb(ctx->out_bev, NULL, NULL, NULL, (void**)&proxy_ctx);

                free_server_proxy_context(proxy_ctx);
                bufferevent_free(ctx->out_bev);
            }
            free_server_context(ctx);
            bufferevent_free(bev);

            return;
        }

        int ciphertext_len = 2 + 2 * de_cipher->tag_size + plaintext_len;
        int addr_len = 0;

        // read target address
        if (ctx->out_bev == NULL) {
            if (plaintext_len < 2) {
                return;
            }

            enum ATYP atyp = plaintext[0];
            int hostname_len = 0;
            int port_offset = 0;

            switch (atyp) {
            case IPv4:
                hostname_len = 4;
                port_offset = 1 + hostname_len;
                addr_len = 1 + hostname_len + 2;
                break;
            case DOMAINNAME:
                hostname_len = plaintext[1];
                port_offset = 1 + 1 + hostname_len;
                addr_len = 1 + 1 + hostname_len + 2;
                break;
            case IPv6:
                hostname_len = 16;
                port_offset = 1 + hostname_len;
                addr_len = 1 + hostname_len + 2;
                break;
            default:
                LOG_WARN("Unexpected program execution: ATYP=0x%x", atyp);
                break;
            }

            if (plaintext_len < addr_len) {
                return;
            }

            // connect to target host
            struct event_base* base = bufferevent_get_base(bev);
            struct bufferevent* proxy_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
            struct server_proxy_context* proxy_ctx = alloc_server_proxy_context(bev);

            bufferevent_setcb(proxy_bev, server_proxy_read_cb, NULL, server_proxy_event_cb,
                              proxy_ctx);
            bufferevent_enable(proxy_bev, EV_READ | EV_WRITE);
            ctx->out_bev = proxy_bev;

            switch (atyp) {
            case IPv4: {
                struct sockaddr_in sock_addr;
                memset(&sock_addr, 0, sizeof sock_addr);
                sock_addr.sin_family = AF_INET;
                sock_addr.sin_addr = *(struct in_addr*)(plaintext + 1);
                sock_addr.sin_port = *(in_port_t*)(plaintext + port_offset);

                bufferevent_socket_connect(proxy_bev, (struct sockaddr*)&sock_addr,
                                           sizeof sock_addr);
            } break;
            case DOMAINNAME: {
                char domain_name[256];
                memset(domain_name, 0, sizeof domain_name);
                memcpy(domain_name, plaintext + 1 + 1, hostname_len);

                uint16_t port = ntohs(*(uint16_t*)(plaintext + port_offset));

                bufferevent_socket_connect_hostname(proxy_bev, dns_base, AF_UNSPEC, domain_name,
                                                    port);
            } break;
            case IPv6: {
                struct sockaddr_in6 sock_addr;
                memset(&sock_addr, 0, sizeof sock_addr);
                sock_addr.sin6_family = AF_INET6;
                sock_addr.sin6_addr = *(struct in6_addr*)(plaintext + 1);
                sock_addr.sin6_port = *(in_port_t*)(plaintext + port_offset);

                bufferevent_socket_connect(proxy_bev, (struct sockaddr*)&sock_addr,
                                           sizeof sock_addr);
            } break;
            default:
                LOG_WARN("Unexpected program execution: ATYP=0x%x", atyp);
                break;
            }
        }

        evbuffer_drain(source, ciphertext_len);
        bufferevent_write(ctx->out_bev, plaintext + addr_len, plaintext_len - addr_len);
    }
}

void server_encrypt_write(struct evbuffer* source, struct evbuffer* destination,
                          struct cipher* en_cipher) {
    // [salt]([encrypted payload length][length tag][encrypted payload][payload tag])...

    static unsigned char zero[MAX_SALT_LENGTH];

    // send [salt]
    if (memcmp(en_cipher->salt, zero, en_cipher->salt_size) == 0) {
        randombytes_buf(en_cipher->salt, en_cipher->salt_size);
        evbuffer_add(destination, en_cipher->salt, en_cipher->salt_size);
    }

    static unsigned char plaintext[MAX_PAYLOAD_LENGTH];
    memset(plaintext, 0, sizeof plaintext);

    // send ([encrypted payload length][length tag][encrypted payload][payload tag])...
    while (evbuffer_get_length(source) != 0) {
        size_t payload_len = evbuffer_remove(source, plaintext, MAX_PAYLOAD_LENGTH);
        size_t plaintext_len = payload_len;
        size_t ciphertext_len = 2 + plaintext_len + 2 * en_cipher->tag_size;

        static unsigned char ciphertext[2 + 2 * MAX_TAG_LENGTH + MAX_PAYLOAD_LENGTH];
        memset(ciphertext, 0, sizeof ciphertext);

        aead_encrypt(en_cipher, plaintext, plaintext_len, ciphertext);
        evbuffer_add(destination, ciphertext, ciphertext_len);
    }
}

void server_read_cb(struct bufferevent* bev, void* arg) {
    struct server_context* ctx = (struct server_context*)arg;
    server_decrypt_read(bev, ctx);
}

void server_event_cb(struct bufferevent* bev, short events, void* arg) {
    if (events & BEV_EVENT_ERROR) {
        LOG_WARN("Error from server socket - %s",
                 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        struct server_context* ctx = (struct server_context*)arg;

        if (ctx->out_bev != NULL) {
            struct server_proxy_context* proxy_ctx;
            bufferevent_getcb(ctx->out_bev, NULL, NULL, NULL, (void**)&proxy_ctx);

            free_server_proxy_context(proxy_ctx);
            bufferevent_free(ctx->out_bev);
        }
        free_server_context(ctx);
        bufferevent_free(bev);
    }
}

void server_accept_cb(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* addr,
                      int socklen, void* arg) {
    struct server_context* ctx = alloc_server_context();
    struct event_base* base = evconnlistener_get_base(listener);
    struct bufferevent* bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (bev == NULL) {
        LOG_EXIT("Cannot create bufferevent.");
    }

    bufferevent_setcb(bev, server_read_cb, NULL, server_event_cb, ctx);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

void server_accept_error_cb(struct evconnlistener* listener, void* arg) {
    int err = EVUTIL_SOCKET_ERROR();
    LOG_EXIT("Got an error %d (%s) on the listener. "
             "Shutting down.",
             err, evutil_socket_error_to_string(err));
}
