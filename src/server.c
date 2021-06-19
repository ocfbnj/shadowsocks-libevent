#include <assert.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <WS2tcpip.h>
#include <WinSock2.h>
#endif

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <sodium.h>

#include "aead.h"
#include "cipher.h"
#include "config.h"
#include "context.h"
#include "logger.h"
#include "proxy.h"
#include "server.h"
#include "socks.h"

extern struct evdns_base* dns_base;

static int connect_tgt_host(uint8_t* addr, struct bufferevent* bev, struct context* ctx) {

    struct event_base* base = bufferevent_get_base(bev);
    struct bufferevent* proxy_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
    struct proxy_context* proxy_ctx = alloc_proxy_context(bev);

    bufferevent_setcb(proxy_bev, proxy_read_cb, NULL, proxy_event_cb, proxy_ctx);
    bufferevent_enable(proxy_bev, EV_READ | EV_WRITE);

    int hostname_len = 0;
    int port_offset = 0;
    enum ATYP atyp = addr[0];

    switch (atyp) {
    case IPv4: {
        hostname_len = 4;
        port_offset = 1 + hostname_len;

        struct sockaddr_in sock_addr;
        memset(&sock_addr, 0, sizeof sock_addr);
        sock_addr.sin_family = AF_INET;
        sock_addr.sin_addr = *(struct in_addr*)(addr + 1);
#ifdef _WIN32
        sock_addr.sin_port = *(USHORT*)(addr + port_offset);
#else
        sock_addr.sin_port = *(in_port_t*)(addr + port_offset);
#endif

        bufferevent_socket_connect(proxy_bev, (struct sockaddr*)&sock_addr, sizeof sock_addr);
    } break;
    case DOMAINNAME: {
        hostname_len = addr[1];
        port_offset = 1 + 1 + hostname_len;

        char domain_name[256];
        memset(domain_name, 0, sizeof domain_name);
        memcpy(domain_name, addr + 1 + 1, hostname_len);

        uint16_t port = ntohs(*(uint16_t*)(addr + port_offset));

        bufferevent_socket_connect_hostname(proxy_bev, dns_base, AF_UNSPEC, domain_name, port);
    } break;
    case IPv6: {
        hostname_len = 16;
        port_offset = 1 + hostname_len;

        struct sockaddr_in6 sock_addr;
        memset(&sock_addr, 0, sizeof sock_addr);
        sock_addr.sin6_family = AF_INET6;
        sock_addr.sin6_addr = *(struct in6_addr*)(addr + 1);
#ifdef _WIN32
        sock_addr.sin6_port = *(USHORT*)(addr + port_offset);
#else
        sock_addr.sin6_port = *(in_port_t*)(addr + port_offset);
#endif

        bufferevent_socket_connect(proxy_bev, (struct sockaddr*)&sock_addr, sizeof sock_addr);
    } break;
    default:
        free_proxy_context(proxy_ctx);
        bufferevent_free(proxy_bev);
        LOG_WARN("Unexpected program execution: ATYP=0x%x", atyp);
        return -1;
    }

    ctx->out_bev = proxy_bev;

    return 0;
}

void server_accept_cb(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* addr,
                      int socklen, void* arg) {
    struct event_base* base = evconnlistener_get_base(listener);
    struct bufferevent* bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    struct cipher_context* c = alloc_cipher_context(AEAD_CHACHA20_POLY1305, get_config(PASSWORD));
    struct bufferevent* e_bev = create_encrypted_bev(bev, c);
    assert(e_bev);

    struct context* ctx = alloc_context();

    bufferevent_setcb(e_bev, server_read_cb, NULL, server_event_cb, ctx);
    bufferevent_enable(e_bev, EV_READ | EV_WRITE);
}

void server_read_cb(struct bufferevent* bev, void* arg) {
    struct context* ctx = (struct context*)arg;

    switch (ctx->stage) {
    case 0: {
        struct evbuffer* in = bufferevent_get_input(bev);
        struct evbuffer* out = bufferevent_get_output(ctx->out_bev);

        evbuffer_add_buffer(out, in);
    } break;
    case 1: {
        uint8_t addr[MAX_ADDR_LENGTH];
        int ret = read_tgt_addr(bufferevent_get_input(bev), addr, NULL);
        if (ret == 0) {
            if (connect_tgt_host(addr, bev, ctx) == 0) {
                ctx->stage = 0;

                server_read_cb(bev, ctx);
            } else {
                if (ctx->out_bev != NULL) {
                    struct proxy_context* proxy_ctx;
                    bufferevent_getcb(ctx->out_bev, NULL, NULL, NULL, (void**)&proxy_ctx);
                    bufferevent_free(ctx->out_bev);
                    free_proxy_context(proxy_ctx);
                }
                bufferevent_free(bev);
                free_context(ctx);
            }
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

void server_event_cb(struct bufferevent* bev, short events, void* arg) {
    if (events & BEV_EVENT_ERROR) {
        LOG_WARN("Error from server socket: %s",
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
