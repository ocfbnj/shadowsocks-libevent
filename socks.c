#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include "config.h"
#include "context.h"
#include "logger.h"
#include "socks.h"

int handshake(struct evbuffer* buf, struct context* ctx) {
    /*
        client message:

        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
    */
    uint8_t* req_data = evbuffer_pullup(buf, 2);
    if (req_data == NULL) {
        return -2;
    }

    if (req_data[0] != 0x05) {
        LOG_WARN("No supported version 0x%x from client", req_data[0]);
        return -1;
    }

    int n_methods = (int)req_data[1];
    if (evbuffer_get_length(buf) < 2 + n_methods) {
        return -2;
    }

    uint8_t methods[255];
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

    int i = 0;
    for (; i < n_methods; i++) {
        int method = (int)methods[i];

        if (method == 0x00) {
            break;
        }
    }

    if (i == n_methods) {
        LOG_WARN("No supported methods from client");
        return -1;
    }

    return 0;
}

int read_tgt_addr(struct evbuffer* r, uint8_t* addr, size_t* addr_len) {
    uint8_t* data = evbuffer_pullup(r, 2);
    if (data == NULL) {
        return -2;
    }

    size_t len = 0;
    enum ATYP atyp = (int)data[0];

    switch (atyp) {
    case IPv4:
        len = 1 + 4 + 2;
        break;
    case DOMAINNAME:
        len = 1 + 1 + (int)data[1] + 2;
        break;
    case IPv6:
        len = 1 + 16 + 2;
        break;
    default:
        LOG_WARN("Unknown address type: 0x%x", atyp);
        return -1;
    }

    data = evbuffer_pullup(r, len);
    if (data == NULL) {
        return -2;
    }

    if (addr_len != NULL) {
        *addr_len = len;
    }

    memcpy(addr, data, len);
    evbuffer_drain(r, len);

    return 0;
}
