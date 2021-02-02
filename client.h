#ifndef CLIENT_H
#define CLIENT_H

#include "socks.h"

#ifdef __cplusplus
extern "C" {
#endif

struct evbuffer;
struct bufferevent;
struct client_context;
struct sockaddr;
struct cipher;
struct evconnlistener;

struct client_context {
    int stage;
    unsigned char tgt_addr[MAX_ADDR_LENGTH];
    struct cipher* en_cipher;
    struct bufferevent* out_bev;
};

struct client_context* alloc_client_context();
void free_client_context(struct client_context* ctx);

void client_accept_error_cb(struct evconnlistener* listener, void* ctx);
void client_accept_cb(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* addr,
                      int socklen, void* arg);

void client_read_cb(struct bufferevent* bev, void* ctx);
void client_write_cb(struct bufferevent* bev, void* ctx);
void client_event_cb(struct bufferevent* bev, short events, void* ctx);

void client_encrypt_write(struct evbuffer* source, struct evbuffer* destination,
                          unsigned char* tgt_addr, struct cipher* en_cipher);
void client_decrypt_read(struct evbuffer* source, struct evbuffer* destination,
                         struct cipher* de_cipher);

#ifdef __cplusplus
}
#endif

#endif
