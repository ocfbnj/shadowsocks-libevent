#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/listener.h>

#include "client.h"
#include "config.h"
#include "logger.h"
#include "tcp.h"

void tcp_client() {
    struct event_base* base = event_base_new();
    if (base == NULL) {
        LOG_EXIT("Cannot create event_base.");
    }

    // listen socket
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof listen_addr);
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons((int)strtol(get_config(LOCAL_PORT), NULL, 10));
    listen_addr.sin_addr.s_addr = INADDR_ANY;

    struct evconnlistener* listener = evconnlistener_new_bind(
        base, client_accept_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr*)&listen_addr, sizeof listen_addr);
    if (listener == NULL) {
        LOG_EXIT("Cannot create evconnlistener.");
    }
    evconnlistener_set_error_cb(listener, client_accept_error_cb);

    // log listen information of local server
    char addr_str[STR_ADDR_LEN];
    str_addr(addr_str, sizeof addr_str, (struct sockaddr*)&listen_addr);
    LOG_MSG("Listen on %s", addr_str);

    event_base_dispatch(base);

    // The code shouldn't get there.
    LOG_WARN("Unexpected program execution: event_base_dispatch() returned.");

    evconnlistener_free(listener);
    event_base_free(base);
}

// TODO
void tcp_server() {}

void str_addr(char* str, int str_len, struct sockaddr* addr) {
    assert(str_len >= STR_ADDR_LEN);

    static char ip[INET6_ADDRSTRLEN];
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in* in = (struct sockaddr_in*)addr;
        evutil_inet_ntop(AF_INET, &in->sin_addr, ip, sizeof(ip));
        sprintf(str, "%s:%hu", ip, ntohs(in->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)addr;
        evutil_inet_ntop(AF_INET6, &in6->sin6_addr, ip, sizeof(ip));
        sprintf(str, "%s:%hu", ip, ntohs(in6->sin6_port));
    } else {
        strncpy((str), "Unknown", 8);
    }
}
