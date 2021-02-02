#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SUBKEY_INFO ((const unsigned char*)"ss-subkey")
#define SUBKEY_INFO_LEN 9

#define MAX_KEY_LENGTH 32
#define MAX_NONCE_LENGTH 12
#define MAX_SALT_LENGTH 32
#define MAX_TAG_LENGTH 16

enum method { AEAD_CHACHA20_POLY1305 };

struct cipher {
    enum method method;

    unsigned char key[MAX_KEY_LENGTH];
    size_t key_size;

    unsigned char nonce[MAX_NONCE_LENGTH];
    size_t nonce_size;

    unsigned char salt[MAX_SALT_LENGTH];
    size_t salt_size;

    size_t tag_size;
};

struct cipher* alloc_cipher(enum method m, const char* password);
void free_cipher(struct cipher* c);

void HKDF_SHA1(const unsigned char* key, size_t key_len, const unsigned char* salt, size_t salt_len,
               const unsigned char* info, size_t info_len, unsigned char* out);

void AEAD_CHACHA20_POLY1305_HKDF_SHA1(const unsigned char* key, const unsigned char* salt,
                                      unsigned char* out);

#ifdef __cplusplus
}
#endif

#endif
