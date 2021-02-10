#ifndef AEAD_H
#define AEAD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SUBKEY_INFO ((const unsigned char*)"ss-subkey")
#define SUBKEY_INFO_LEN 9

#define MAX_PAYLOAD_LENGTH 0x3FFF

struct cipher;
struct cipher_context;

// On success, 0 is returned.
// On error, -1 is returned.
int aead_encrypt(struct cipher* c, const uint8_t* plaintext, size_t plaintext_len,
                 uint8_t* ciphertext, size_t* ciphertext_len);

// On success, 0 is returned.
// Returned -2 indicates that the data is too short and needs to be tried again.
// Returned -1 on error.
int aead_decrypt(struct cipher* c, const uint8_t* ciphertext, size_t ciphertext_len,
                 uint8_t* plaintext, size_t* plaintext_len);

// create_encrypted_bev returns a encrypted bufferevent providing confidentiality for bev.
struct bufferevent* create_encrypted_bev(struct bufferevent* bev, struct cipher_context* c);

// HKDF_SHA1 takes a secret key, a non-secret salt, an info string, and produces
// a subkey that is cryptographically strong even if the input secret key is weak.
void HKDF_SHA1(const uint8_t* key, size_t key_len, const uint8_t* salt, size_t salt_len,
               const uint8_t* info, size_t info_len, uint8_t* out);
void AEAD_CHACHA20_POLY1305_HKDF_SHA1(const unsigned char* key, const unsigned char* salt,
                                      unsigned char* out);

#ifdef __cplusplus
}
#endif

#endif
