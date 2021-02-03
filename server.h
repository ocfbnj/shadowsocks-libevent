#ifndef SERVER_H
#define SERVER_H

#include <event2/util.h>

#ifdef __cplusplus
extern "C" {
#endif

struct evconnlistener;
struct sockaddr;
struct bufferevent;
struct evbuffer;
struct cipher;

struct server_context {
    struct cipher* de_cipher;
    struct bufferevent* out_bev;
};

struct server_context* alloc_server_context();
void free_server_context(struct server_context* ctx);

void server_accept_error_cb(struct evconnlistener* listener, void* arg);
void server_accept_cb(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* addr,
                      int socklen, void* arg);

void server_read_cb(struct bufferevent* bev, void* arg);
void server_event_cb(struct bufferevent* bev, short events, void* arg);

void server_decrypt_read(struct bufferevent* bev, struct server_context* ctx);
void server_encrypt_write(struct evbuffer* source, struct evbuffer* destination,
                          struct cipher* en_cipher);

#ifdef __cplusplus
}
#endif

#endif
