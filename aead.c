#include <assert.h>
#include <string.h>

#include <arpa/inet.h>

#include <mbedtls/hkdf.h>
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

void HKDF_SHA1(const unsigned char* key, size_t key_len, const unsigned char* salt, size_t salt_len,
               const unsigned char* info, size_t info_len, unsigned char* out) {
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_string("SHA1");
    mbedtls_hkdf(md_info, salt, salt_len, key, key_len, info, info_len, out, key_len);
}

void AEAD_CHACHA20_POLY1305_HKDF_SHA1(const unsigned char* key, const unsigned char* salt,
                                      unsigned char* out) {
    HKDF_SHA1(key, 32, salt, 32, SUBKEY_INFO, SUBKEY_INFO_LEN, out);
}
