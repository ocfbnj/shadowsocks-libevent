#ifndef SOCKS_H
#define SOCKS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// The maximum length of target address (1 + 1 + 255 + 2).
#define MAX_ADDR_LENGTH 259

struct evbuffer;

// SOCKS request command defined in RFC 1928 section 4.
enum CMD { CONNECT = 0x01, BIND = 0x02, UDP_ASSOCIATE = 0x03 };

// SOCKS address type defined in RFC 1928 section 5.
enum ATYP { IPv4 = 0x01, DOMAINNAME = 0x03, IPv6 = 0x04 };

// Handling the first stage of the handshake process of the SOCKS5 protocol.
int handshake(struct evbuffer* buf, struct context* ctx);

// Read a SOCK5 address from r.
int read_tgt_addr(struct evbuffer* r, uint8_t* addr, size_t* addr_len);

#ifdef __cplusplus
}
#endif

#endif
