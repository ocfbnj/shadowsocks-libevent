#ifndef SOCKS_H
#define SOCKS_H

#ifdef __cplusplus
extern "C" {
#endif

// Conventionally SOCK port defined in RFC 1928 section 3.
// #define PORT 1080

// The maximum length of target address (1 + 1 + 255 + 2).
#define MAX_ADDR_LENGTH 259

// 3 + MAX_ADDR_LENGTH
// #define MAX_MSG_LENGTH 262

struct bufferevent;
struct client_context;

void stage1(struct bufferevent* bev, struct client_context* status);
void stage2(struct bufferevent* bev, struct client_context* status);

// SOCKS request command defined in RFC 1928 section 4.
enum CMD { CONNECT = 0x01, BIND = 0x02, UDP_ASSOCIATE = 0x03 };

// SOCKS address type defined in RFC 1928 section 5.
enum ATYP { IPv4 = 0x01, DOMAINNAME = 0x03, IPv6 = 0x04 };

#ifdef __cplusplus
}
#endif

#endif
