#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "config.h"
#include "logger.h"
#include "tcp.h"

void print_usage() {
    printf("usage: \n"
           "        --client                   Client mode. (Default)\n"
           "        --server                   Server mode.\n\n"
           "        -s <server_host>           Host name or IP address of your remote server.\n"
           "        -p <server_port>           Port number of your remote server.\n"
           "        -l <local_port>            Port number of your local server.\n"
           "        -k <password>              Password of your remote server.\n");
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    {
        WSADATA wsaData;
        WORD version = MAKEWORD(2, 2);
        WSAStartup(version, &wsaData);
    }
#endif

    if (sodium_init() < 0) {
        LOG_EXIT("sodium_init() failed.");
    }

    for (int i = 1; i < argc; i++) {
        if (!strcmp("--help", argv[i]) || !strcmp("-h", argv[i])) {
            print_usage();
            return 0;
        }

        if (!strcmp("--server", argv[i])) {
            set_mode(SERVER);
            continue;
        }

        if (!strcmp("-s", argv[i])) {
            set_config(SERVER_HOST, argv[++i]);
        } else if (!strcmp("-p", argv[i])) {
            set_config(SERVER_PORT, argv[++i]);
        } else if (!strcmp("-l", argv[i])) {
            set_config(LOCAL_PORT, argv[++i]);
        } else if (!strcmp("-k", argv[i])) {
            set_config(PASSWORD, argv[++i]);
        }
    }

    switch (get_mode()) {
    case SERVER:
        if (!get_config(SERVER_PORT) || !get_config(PASSWORD)) {
            print_usage();
            return 0;
        }
        tcp_server();
        break;
    case CLIENT:
        if (!get_config(LOCAL_PORT) || !get_config(SERVER_HOST) || !get_config(SERVER_PORT) ||
            !get_config(PASSWORD)) {
            print_usage();
            return 0;
        }
        tcp_client();
        break;
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
