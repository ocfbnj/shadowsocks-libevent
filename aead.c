#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include <mbedtls/md.h>
#include <sodium.h>

#include "aead.h"
#include "crypto.h"
#include "logger.h"

static int AEAD_CHACHA20_POLY1305_encrypt(struct cipher* c, const unsigned char* plaintext,
                                          size_t plaintext_len, unsigned char* ciphertext) {
    unsigned char subkey[MAX_KEY_LENGTH];
    AEAD_CHACHA20_POLY1305_HKDF_SHA1(c->key, c->salt, subkey);

    // encrypt length (plaintext_len)
    uint16_t length = htons((uint16_t)plaintext_len & MAX_PAYLOAD_LENGTH);
    unsigned long long encrypted_len;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &encrypted_len,
                                                  (unsigned char*)&length, 2, NULL, 0, NULL,
                                                  c->nonce, subkey) < 0) {
        LOG_WARN("Encrypt failed.");
        return -1;
    }

    assert(encrypted_len == 2 + c->tag_size);
    sodium_increment(c->nonce, c->nonce_size);

    // encrypt payload (plaintext)
    if (crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext + encrypted_len, &encrypted_len,
                                                  plaintext, plaintext_len, NULL, 0, NULL, c->nonce,
                                                  subkey) < 0) {
        LOG_WARN("Encrypt failed.");
        return -1;
    }

    assert(encrypted_len == plaintext_len + c->tag_size);
    sodium_increment(c->nonce, c->nonce_size);

    return 0;
}

int aead_encrypt(struct cipher* c, const unsigned char* plaintext, size_t plaintext_len,
                 unsigned char* ciphertext) {
    switch (c->method) {
    case AEAD_CHACHA20_POLY1305:
        return AEAD_CHACHA20_POLY1305_encrypt(c, plaintext, plaintext_len, ciphertext);
    default:
        break;
    }

    return -1;
}

static int AEAD_CHACHA20_POLY1305_decrypt(struct cipher* c, const unsigned char* ciphertext,
                                          size_t ciphertext_len, unsigned char* plaintext) {
    if (ciphertext_len < 2 + c->tag_size) {
        return -2;
    }

    unsigned char subkey[MAX_KEY_LENGTH];
    AEAD_CHACHA20_POLY1305_HKDF_SHA1(c->key, c->salt, subkey);

    // decrypt length
    unsigned long long decrypted_len;
    uint16_t length;
    if (crypto_aead_chacha20poly1305_ietf_decrypt((unsigned char*)&length, &decrypted_len, NULL,
                                                  ciphertext, 2 + c->tag_size, NULL, 0, c->nonce,
                                                  subkey) < 0) {
        LOG_WARN("Decrypt failed.");
        return -1;
    }

    assert(decrypted_len == 2);

    unsigned temp_nonce[MAX_NONCE_LENGTH];
    memcpy(temp_nonce, c->nonce, c->nonce_size);

    length = ntohs(length);
    sodium_increment(c->nonce, c->nonce_size);

    if (ciphertext_len < 2 + c->tag_size + length + c->tag_size) {
        memcpy(c->nonce, temp_nonce, c->nonce_size);

        return -2;
    }

    // decrypt payload
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            plaintext, &decrypted_len, NULL, ciphertext + 2 + c->tag_size, length + c->tag_size,
            NULL, 0, c->nonce, subkey) < 0) {
        LOG_WARN("Decrypt failed.");
        return -1;
    }

    assert(decrypted_len == length);
    sodium_increment(c->nonce, c->nonce_size);

    return length;
}

int aead_decrypt(struct cipher* c, const unsigned char* ciphertext, size_t ciphertext_len,
                 unsigned char* plaintext) {
    switch (c->method) {
    case AEAD_CHACHA20_POLY1305:
        return AEAD_CHACHA20_POLY1305_decrypt(c, ciphertext, ciphertext_len, plaintext);
    default:
        break;
    }

    return -1;
}

void derive_key(const char* password, unsigned char* key, size_t key_len) {
    size_t datal;
    datal = strlen((const char*)password);

    const mbedtls_md_info_t* md = mbedtls_md_info_from_string("MD5");
    if (md == NULL) {
        LOG_EXIT("MD5 Digest not found in crypto library");
    }

    mbedtls_md_context_t c;
    unsigned char md_buf[MBEDTLS_MD_MAX_SIZE];
    int addmd;
    unsigned int i, j, mds;

    mds = mbedtls_md_get_size(md);
    memset(&c, 0, sizeof(mbedtls_md_context_t));
    mbedtls_md_setup(&c, md, 0);

    for (j = 0, addmd = 0; j < key_len; addmd++) {
        mbedtls_md_starts(&c);
        if (addmd) {
            mbedtls_md_update(&c, md_buf, mds);
        }
        mbedtls_md_update(&c, (uint8_t*)password, datal);
        mbedtls_md_finish(&c, &(md_buf[0]));

        for (i = 0; i < mds; i++, j++) {
            if (j >= key_len)
                break;
            key[j] = md_buf[i];
        }
    }

    mbedtls_md_free(&c);
}
