#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "client.h"
#include "config.h"
#include "crypto.h"
#include "logger.h"
#include "proxy.h"

struct client_proxy_context* alloc_client_proxy_context(struct bufferevent* bev) {
    struct client_proxy_context* context =
        (struct client_proxy_context*)calloc(1, sizeof(struct client_proxy_context));
    if (context == NULL) {
        LOG_EXIT("Cannot create client_proxy_context");
    }

    context->de_cipher = alloc_cipher(AEAD_CHACHA20_POLY1305, get_config(PASSWORD));
    context->out_bev = bev;

    return context;
}

void free_client_proxy_context(struct client_proxy_context* ctx) {
    free_cipher(ctx->de_cipher);
    free(ctx);
}

void client_proxy_read_cb(struct bufferevent* bev, void* ctx) {
    struct client_proxy_context* status = (struct client_proxy_context*)ctx;
    struct evbuffer* in = bufferevent_get_input(bev);
    struct evbuffer* out = bufferevent_get_output(status->out_bev);

    client_decrypt_read(in, out, status->de_cipher);
}

void client_proxy_event_cb(struct bufferevent* bev, short events, void* arg) {
    struct client_proxy_context* ctx = (struct client_proxy_context*)arg;

    if (events & BEV_EVENT_CONNECTED) {
        unsigned char resp_data[10] = "\x05\x00\x00\x01";
        bufferevent_write(ctx->out_bev, resp_data, sizeof(resp_data));
    } else {
        if (events & BEV_EVENT_ERROR) {
            LOG_WARN("Error from proxy socket - %s",
                     evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        }

        if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
            if (ctx->out_bev) {
                bufferevent_free(ctx->out_bev);
            }
            bufferevent_free(bev);
            free_client_proxy_context(ctx);
        }
    }
}
