#include <stddef.h>

#include "config.h"

static const char* server_host;
static const char* server_port;
static const char* local_port;
static const char* password;
static int server_mode;

void set_mode(enum mode m) {
    switch (m) {
    case SERVER:
        server_mode = 1;
        break;
    case CLIENT:
        server_mode = 0;
        break;
    default:
        break;
    }
}

enum mode get_mode() { return server_mode ? SERVER : CLIENT; }

const char* get_config(enum config c) {
    const char* ret = NULL;

    switch (c) {
    case SERVER_HOST:
        ret = server_host;
        break;
    case SERVER_PORT:
        ret = server_port;
        break;
    case LOCAL_PORT:
        ret = local_port;
        break;
    case PASSWORD:
        ret = password;
        break;
    default:
        break;
    }

    return ret;
}

void set_config(enum config c, const char* value) {
    switch (c) {
    case SERVER_HOST:
        server_host = value;
        break;
    case SERVER_PORT:
        server_port = value;
        break;
    case LOCAL_PORT:
        local_port = value;
        break;
    case PASSWORD:
        password = value;
        break;
    default:
        break;
    }
}
