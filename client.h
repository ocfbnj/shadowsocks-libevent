#ifndef CLIENT_H
#define CLIENT_H

#include <event2/util.h>

#ifdef __cplusplus
extern "C" {
#endif

struct evconnlistener;
struct sockaddr;
struct bufferevent;

void client_accept_cb(struct evconnlistener* listener, evutil_socket_t fd, struct sockaddr* addr,
                      int socklen, void* arg);

void client_read_cb(struct bufferevent* bev, void* arg);
void client_event_cb(struct bufferevent* bev, short events, void* arg);

#ifdef __cplusplus
}
#endif

#endif
