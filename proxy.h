#ifndef PROXY_H
#define PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

struct bufferevent;

struct proxy_context {
    struct bufferevent* out_bev;
};

struct proxy_context* alloc_proxy_context(struct bufferevent* bev);
void free_proxy_context(struct proxy_context* ctx);

void proxy_read_cb(struct bufferevent* bev, void* arg);
void proxy_event_cb(struct bufferevent* bev, short events, void* arg);

#ifdef __cplusplus
}
#endif

#endif
