#ifndef TCP_H
#define TCP_H

#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

// INET6_ADDRSTRLEN + 1 + 5
#define STR_ADDR_LEN 52

void tcp_client();
void tcp_server();
void str_addr(char* str, int str_len, struct sockaddr* addr);

#ifdef __cplusplus
}
#endif

#endif
