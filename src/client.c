#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <sodium.h>

#include "aead.h"
#include "cipher.h"
#include "client.h"
#include "config.h"
#include "context.h"
#include "logger.h"
#include "proxy.h"
#include "socks.h"
#include "tcp.h"

extern struct evdns_base* dns_base;

void client_accept_cb(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* addr,
                      int socklen, void* arg) {
    struct context* ctx = alloc_context();
    struct event_base* base = evconnlistener_get_base(listener);
    struct bufferevent* bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    assert(bev);

    bufferevent_setcb(bev, client_read_cb, NULL, client_event_cb, ctx);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
}

void client_read_cb(struct bufferevent* bev, void* arg) {
    struct context* ctx = (struct context*)arg;

    switch (ctx->stage) {
    case 0: {
        struct evbuffer* in = bufferevent_get_input(bev);
        struct evbuffer* out = bufferevent_get_output(ctx->out_bev);

        evbuffer_add_buffer(out, in);
    } break;
    case 1: {
        int ret = handshake(bufferevent_get_input(bev), ctx);
        if (ret == 0) {
            bufferevent_write(bev, "\x05\x00", 2);
            ctx->stage = 2;

            client_read_cb(bev, ctx);
        } else if (ret == -2) {
            return;
        } else if (ret == -1) {
            if (ctx->out_bev != NULL) {
                struct proxy_context* proxy_ctx;
                bufferevent_getcb(ctx->out_bev, NULL, NULL, NULL, (void**)&proxy_ctx);
                bufferevent_free(ctx->out_bev);
                free_proxy_context(proxy_ctx);
            }
            bufferevent_free(bev);
            free_context(ctx);
        }
    } break;
    case 2: {
        struct evbuffer* r = bufferevent_get_input(bev);
        if (evbuffer_get_length(r) < 3) {
            return;
        }
        evbuffer_drain(r, 3);

        uint8_t addr[MAX_ADDR_LENGTH];
        size_t addr_len = 0;
        int ret = read_tgt_addr(r, addr, &addr_len);
        if (ret == 0) {
            struct event_base* base = bufferevent_get_base(bev);
            struct bufferevent* proxy_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
            struct cipher_context* c =
                alloc_cipher_context(AEAD_CHACHA20_POLY1305, get_config(PASSWORD));
            struct bufferevent* e_proxy_bev = create_encrypted_bev(proxy_bev, c);
            assert(e_proxy_bev);

            struct proxy_context* proxy_ctx = alloc_proxy_context(bev);
            const char* hostname = get_config(SERVER_HOST);
            int port = atoi(get_config(SERVER_PORT));

            bufferevent_setcb(e_proxy_bev, proxy_read_cb, NULL, proxy_event_cb, proxy_ctx);
            bufferevent_enable(e_proxy_bev, EV_READ | EV_WRITE);
            bufferevent_socket_connect_hostname(e_proxy_bev, dns_base, AF_UNSPEC, hostname, port);

            uint8_t resp_data[10] = "\x05\x00\x00\x01";
            bufferevent_write(bev, resp_data, sizeof(resp_data));
            bufferevent_write(e_proxy_bev, addr, addr_len);

            ctx->out_bev = e_proxy_bev;
            ctx->stage = 0;

            client_read_cb(bev, ctx);
        } else if (ret == -2) {
            return;
        } else if (ret == -1) {
            if (ctx->out_bev != NULL) {
                struct proxy_context* proxy_ctx;
                bufferevent_getcb(ctx->out_bev, NULL, NULL, NULL, (void**)&proxy_ctx);
                bufferevent_free(ctx->out_bev);
                free_proxy_context(proxy_ctx);
            }
            bufferevent_free(bev);
            free_context(ctx);
        }
    } break;
    default:
        break;
    }
}

void client_event_cb(struct bufferevent* bev, short events, void* arg) {
    if (events & BEV_EVENT_ERROR) {
        LOG_WARN("Error from client socket: %s",
                 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        struct context* ctx = (struct context*)arg;

        if (ctx->out_bev != NULL) {
            struct proxy_context* proxy_ctx;
            bufferevent_getcb(ctx->out_bev, NULL, NULL, NULL, (void**)&proxy_ctx);
            bufferevent_free(ctx->out_bev);
            free_proxy_context(proxy_ctx);
        }
        bufferevent_free(bev);
        free_context(ctx);
    }
}
