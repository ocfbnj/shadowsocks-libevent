#ifndef PROXY_H
#define PROXY_H

#ifdef __cplusplus
extern "C" {
#endif

struct bufferevent;
struct client_proxy_context;
struct cipher;

struct client_proxy_context {
    struct bufferevent* out_bev;
    struct cipher* de_cipher;
};

struct server_proxy_context {
    struct bufferevent* out_bev;
    struct cipher* en_cipher;
};

struct client_proxy_context* alloc_client_proxy_context(struct bufferevent* bev);
void free_client_proxy_context(struct client_proxy_context* ctx);

struct server_proxy_context* alloc_server_proxy_context(struct bufferevent* bev);
void free_server_proxy_context(struct server_proxy_context* ctx);

void client_proxy_read_cb(struct bufferevent* bev, void* ctx);
void client_proxy_event_cb(struct bufferevent* bev, short events, void* ctx);

void server_proxy_read_cb(struct bufferevent* bev, void* arg);
void server_proxy_event_cb(struct bufferevent* bev, short events, void* arg);

#ifdef __cplusplus
}
#endif

#endif
