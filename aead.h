#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PAYLOAD_LENGTH 0x3FFF

struct cipher;

// On success, 0 is returned.
// On error, -1 is returned.
int aead_encrypt(struct cipher* c, const unsigned char* plaintext, size_t plaintext_len,
                 unsigned char* ciphertext);

// Returned the length of ciphertext on success.
// Returned -2 indicates that the data is too short and needs to be tried again.
// Returned -1 on error.
int aead_decrypt(struct cipher* c, const unsigned char* ciphertext, size_t ciphertext_len,
                 unsigned char* plaintext);

// Copy from shadowsocks-libev.
void derive_key(const char* password, unsigned char* key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif
