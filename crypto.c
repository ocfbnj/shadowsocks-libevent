#include <stdlib.h>

#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

#include "aead.h"
#include "crypto.h"
#include "logger.h"

struct cipher* alloc_cipher(enum method m, const char* password) {
    if (m == AEAD_CHACHA20_POLY1305) {
        struct cipher* c = calloc(1, sizeof(struct cipher));
        if (c == NULL) {
            LOG_EXIT("Cannot create cipher.");
        }

        c->key_size = 32;
        c->salt_size = 32;
        c->nonce_size = 12;
        c->tag_size = 16;

        if (password) {
            derive_key(password, c->key, c->key_size);
        }

        return c;
    }

    return NULL;
}

void free_cipher(struct cipher* c) {
    free(c);
}

void HKDF_SHA1(const unsigned char* key, size_t key_len, const unsigned char* salt, size_t salt_len,
               const unsigned char* info, size_t info_len, unsigned char* out) {
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_string("SHA1");
    mbedtls_hkdf(md_info, salt, salt_len, key, key_len, info, info_len, out, key_len);
}

void AEAD_CHACHA20_POLY1305_HKDF_SHA1(const unsigned char* key, const unsigned char* salt,
                                      unsigned char* out) {
    HKDF_SHA1(key, 32, salt, 32, SUBKEY_INFO, SUBKEY_INFO_LEN, out);
}
