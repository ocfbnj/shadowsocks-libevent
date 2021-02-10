#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/bufferevent.h>
#include <event2/dns.h>
#include <event2/event.h>
#include <event2/listener.h>

#include "client.h"
#include "config.h"
#include "logger.h"
#include "server.h"
#include "tcp.h"

struct evdns_base* dns_base;

static void accept_error_cb(struct evconnlistener* listener, void* arg) {
    LOG_EXIT("Got an error on the listener: %s",
             evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
}

static void listen_on(const char* port, evconnlistener_cb accept_cb) {
    struct event_base* base = event_base_new();
    if (base == NULL) {
        LOG_EXIT("Cannot create event_base");
    }

    dns_base = evdns_base_new(base, 1);

    struct evutil_addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = EVUTIL_AI_ADDRCONFIG | EVUTIL_AI_PASSIVE;

    struct evutil_addrinfo* res;
    if (evutil_getaddrinfo(NULL, port, &hints, &res) != 0) {
        LOG_EXIT("evutil_getaddrinfo() error");
    }

    struct evconnlistener* listener =
        evconnlistener_new_bind(base, accept_cb, NULL, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                -1, res->ai_addr, res->ai_addrlen);
    if (listener == NULL) {
        LOG_EXIT("Cannot create evconnlistener");
    }
    evconnlistener_set_error_cb(listener, accept_error_cb);

    // log listen information
    char addr_str[STR_ADDR_LEN];
    str_addr(addr_str, sizeof addr_str, res->ai_addr);
    LOG_MSG("Listen on %s", addr_str);

    evutil_freeaddrinfo(res);

    event_base_dispatch(base);

    // The code shouldn't get there.
    LOG_WARN("Unexpected program execution: event_base_dispatch() returned");

    evdns_base_free(dns_base, 0);
    evconnlistener_free(listener);
    event_base_free(base);
}

void tcp_client() { listen_on(get_config(LOCAL_PORT), client_accept_cb); }

void tcp_server() { listen_on(get_config(SERVER_PORT), server_accept_cb); }

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
