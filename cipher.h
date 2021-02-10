#ifndef CIPHER_H
#define CIPHER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_KEY_LENGTH 32
#define MAX_NONCE_LENGTH 12
#define MAX_SALT_LENGTH 32
#define MAX_TAG_LENGTH 16

enum method { AEAD_CHACHA20_POLY1305 };

struct cipher {
    enum method method;

    uint8_t key[MAX_KEY_LENGTH];
    uint8_t salt[MAX_SALT_LENGTH];
    uint8_t nonce[MAX_NONCE_LENGTH];

    size_t key_size;
    size_t salt_size;
    size_t nonce_size;
    size_t tag_size;

    int hava_salt;
};

struct cipher_context {
    struct cipher* de_cipher;
    struct cipher* en_cipher;
};

struct cipher* alloc_cipher(enum method m, const char* password);
void free_cipher(struct cipher* c);

struct cipher_context* alloc_cipher_context(enum method m, const char* password);
void free_cipher_context(void* c);

// Copy from shadowsocks-libev.
void derive_key(const char* password, uint8_t* key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif
