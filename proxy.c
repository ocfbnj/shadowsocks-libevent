#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include "context.h"
#include "logger.h"
#include "proxy.h"
#include "server.h"

struct proxy_context* alloc_proxy_context(struct bufferevent* bev) {
    struct proxy_context* ctx = calloc(1, sizeof(struct proxy_context));
    assert(ctx);

    ctx->out_bev = bev;
    return ctx;
}

void free_proxy_context(struct proxy_context* ctx) { free(ctx); }

void proxy_read_cb(struct bufferevent* bev, void* arg) {
    struct proxy_context* ctx = (struct proxy_context*)arg;
    struct evbuffer* in = bufferevent_get_input(bev);
    struct evbuffer* out = bufferevent_get_output(ctx->out_bev);

    evbuffer_add_buffer(out, in);
}

void proxy_event_cb(struct bufferevent* bev, short events, void* arg) {
    struct proxy_context* proxy_ctx = (struct proxy_context*)arg;

    if (events & BEV_EVENT_ERROR) {
        LOG_WARN("Error from proxy socket: %s",
                 evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        if (proxy_ctx->out_bev) {
            struct context* ctx;
            bufferevent_getcb(proxy_ctx->out_bev, NULL, NULL, NULL, (void**)&ctx);
            bufferevent_free(proxy_ctx->out_bev);
            free_context(ctx);
        }
        bufferevent_free(bev);
        free_proxy_context(proxy_ctx);
    }
}
