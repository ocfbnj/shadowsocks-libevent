#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include "client.h"
#include "config.h"
#include "crypto.h"
#include "logger.h"
#include "proxy.h"
#include "socks.h"
#include "tcp.h"

void stage1(struct bufferevent* bev, struct client_context* ctx) {
    struct evbuffer* buf = bufferevent_get_input(bev);

    /*
        client message:

        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
    */
    unsigned char* req_data = evbuffer_pullup(buf, 2);
    if (req_data == NULL) {
        return;
    }

    if (req_data[0] != 0x05) {
        LOG_WARN("No supported version 0x%x from client.", req_data[0]);

        if (ctx->out_bev != NULL) {
            bufferevent_free(ctx->out_bev);
        }
        bufferevent_free(bev);
        free_client_context(ctx);
        return;
    }

    int n_methods = (int)req_data[1];
    if (evbuffer_get_length(buf) < 2 + n_methods) {
        return;
    }

    unsigned char methods[255];
    evbuffer_drain(buf, 2);
    evbuffer_remove(buf, methods, n_methods);

    /*
        response to a method selection message:

        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+
    */
    unsigned char resp_data[2] = {0x05, 0xff};

    int i = 0;
    for (; i < n_methods; i++) {
        int method = (int)methods[i];

        if (method == 0x00) {
            // ready to get the address
            resp_data[1] = 0x00;
            bufferevent_write(bev, resp_data, 2);
            break;
        }
    }

    if (i == n_methods) {
        LOG_WARN("No supported methods from client.");
        ctx->stage = -1;
        bufferevent_write(bev, resp_data, 2);
        return;
    }

    ctx->stage++;
}

void stage2(struct bufferevent* bev, struct client_context* ctx) {
    struct evbuffer* buf = bufferevent_get_input(bev);
    /*
        client message:

        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X’00’ |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

        o VER protocol version: X’05’
        o CMD
            o CONNECT X’01’
            o BIND X’02’
            o UDP ASSOCIATE X’03’
        o RSV RESERVED
        o ATYP address type of following address
            o IP V4 address: X’01’
            o DOMAINNAME: X’03’
            o IP V6 address: X’04’
        o DST.ADDR desired destination address
        o DST.PORT desired destination port in network octet order
    */
    unsigned char* req_data = evbuffer_pullup(buf, 4);
    if (req_data == NULL) {
        return;
    }

    // check the version
    if (req_data[0] != 0x05) {
        LOG_WARN("No supported version 0x%x from client.", req_data[0]);

        if (ctx->out_bev != NULL) {
            bufferevent_free(ctx->out_bev);
        }
        bufferevent_free(bev);
        free_client_context(ctx);
        return;
    }

    enum CMD cmd = (int)req_data[1];
    enum ATYP atyp = (int)req_data[3];

    if (cmd == CONNECT) {
        switch (atyp) {
        case IPv4: {
            if (evbuffer_get_length(buf) < 4 + 4 + 2) {
                LOG_WARN("The client message is too short.");
                return;
            }

            evbuffer_drain(buf, 4 - 1);
            evbuffer_remove(buf, ctx->tgt_addr, 1 + 4 + 2);
        } break;
        case DOMAINNAME: {
            unsigned char* data = evbuffer_pullup(buf, 4 + 1);
            if (data == NULL) {
                LOG_WARN("The client message is too short.");
                return;
            }

            unsigned char len = data[4 + 0];

            if (evbuffer_get_length(buf) < 4 + 1 + len + 2) {
                LOG_WARN("The client message is too short.");
                return;
            }

            evbuffer_drain(buf, 4 - 1);
            evbuffer_remove(buf, ctx->tgt_addr, 1 + 1 + len + 2);
        } break;
        case IPv6: {
            if (evbuffer_get_length(buf) < 4 + 16 + 2) {
                LOG_WARN("The client message is too short.");
                return;
            }

            evbuffer_drain(buf, 4 - 1);
            evbuffer_remove(buf, ctx->tgt_addr, 1 + 16 + 2);
        } break;
        default: {
            LOG_WARN("Unexpected program execution: ATYP=0x%x", atyp);

            unsigned char resp_data[10] = "\x05\x08\x00\x01";
            bufferevent_write(bev, resp_data, sizeof(resp_data));
            ctx->stage = -2;
            return;
        }
        }

        struct event_base* base = bufferevent_get_base(bev);
        struct bufferevent* proxy_bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        struct client_proxy_context* proxy_ctx = alloc_client_proxy_context(bev);

        bufferevent_setcb(proxy_bev, client_proxy_read_cb, NULL, client_proxy_event_cb, proxy_ctx);
        bufferevent_enable(proxy_bev, EV_READ | EV_WRITE);

        // TODO add support to IPv6
        const char* server_host = get_config(SERVER_HOST);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons((int)strtol(get_config(SERVER_PORT), NULL, 10));
        evutil_inet_pton(AF_INET, server_host, &addr.sin_addr);

        // connect to proxy server
        bufferevent_socket_connect(proxy_bev, (struct sockaddr*)&addr, sizeof addr);

        ctx->out_bev = proxy_bev;
    } else {
        LOG_WARN("No supported CMD from client.");

        unsigned char resp_data[10] = "\x05\x07\x00\x01";
        bufferevent_write(bev, resp_data, sizeof(resp_data));
        ctx->stage = -2;
        return;
    }

    // ok
    ctx->stage = 0;
}

size_t read_tgt_addr(unsigned char* tgt_addr, unsigned char* out) {
    switch (tgt_addr[0]) {
    case IPv4:
        memcpy(out, tgt_addr, 1 + 4 + 2);
        return 1 + 4 + 2;
    case DOMAINNAME:
        memcpy(out, tgt_addr, 1 + 1 + tgt_addr[1] + 2);
        return 1 + 1 + tgt_addr[1] + 2;
    case IPv6:
        memcpy(out, tgt_addr, 1 + 16 + 2);
        return 1 + 16 + 2;
    default:
        break;
    }

    LOG_WARN("Unexpected program execution.");

    return 0;
}
