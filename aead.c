#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <mbedtls/hkdf.h>
#include <sodium.h>

#include "aead.h"
#include "cipher.h"
#include "logger.h"

static int AEAD_CHACHA20_POLY1305_encrypt(struct cipher* c, const uint8_t* plaintext,
                                          size_t plaintext_len, uint8_t* ciphertext,
                                          size_t* ciphertext_len) {
    uint8_t subkey[MAX_KEY_LENGTH];
    AEAD_CHACHA20_POLY1305_HKDF_SHA1(c->key, c->salt, subkey);

    // encrypt length (plaintext_len)
    uint16_t length = htons((uint16_t)plaintext_len & MAX_PAYLOAD_LENGTH);
    unsigned long long encrypted_len;

    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &encrypted_len, (uint8_t*)&length, 2,
                                              NULL, 0, NULL, c->nonce, subkey);

    assert(encrypted_len == 2 + c->tag_size);
    sodium_increment(c->nonce, c->nonce_size);

    // encrypt payload (plaintext)
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext + encrypted_len, &encrypted_len, plaintext,
                                              plaintext_len, NULL, 0, NULL, c->nonce, subkey);

    assert(encrypted_len == plaintext_len + c->tag_size);
    sodium_increment(c->nonce, c->nonce_size);

    if (ciphertext_len != NULL) {
        *ciphertext_len = encrypted_len + 2 + c->tag_size;
    }

    return 0;
}

static int AEAD_CHACHA20_POLY1305_decrypt(struct cipher* c, const uint8_t* ciphertext,
                                          size_t ciphertext_len, uint8_t* plaintext,
                                          size_t* plaintext_len) {
    if (ciphertext_len < 2 + c->tag_size) {
        return -2;
    }

    uint8_t subkey[MAX_KEY_LENGTH];
    AEAD_CHACHA20_POLY1305_HKDF_SHA1(c->key, c->salt, subkey);

    // decrypt length
    unsigned long long decrypted_len;
    uint16_t length;
    if (crypto_aead_chacha20poly1305_ietf_decrypt((uint8_t*)&length, &decrypted_len, NULL,
                                                  ciphertext, 2 + c->tag_size, NULL, 0, c->nonce,
                                                  subkey) < 0) {
        LOG_WARN("Decrypt failed");
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
        LOG_WARN("Decrypt failed");
        return -1;
    }

    assert(decrypted_len == length);
    sodium_increment(c->nonce, c->nonce_size);

    if (plaintext_len != NULL) {
        *plaintext_len = decrypted_len;
    }

    return 0;
}

static int read_salt(struct evbuffer* r, struct cipher* c) {
    if (c->hava_salt) {
        return 0;
    }

    uint8_t* data = evbuffer_pullup(r, c->salt_size);
    if (data == NULL) {
        return -2;
    }

    memcpy(c->salt, data, c->salt_size);
    evbuffer_drain(r, c->salt_size);
    c->hava_salt = 1;

    return 0;
}

static int write_salt(struct evbuffer* w, struct cipher* c) {
    if (c->hava_salt) {
        return 0;
    }

    randombytes_buf(c->salt, c->salt_size);
    evbuffer_add(w, c->salt, c->salt_size);
    c->hava_salt = 1;

    return 0;
}

static enum bufferevent_filter_result
decrypt_filter_cb(struct evbuffer* source, struct evbuffer* destination, ev_ssize_t dst_limit,
                  enum bufferevent_flush_mode mode, void* arg) {
    assert(dst_limit == -1);
    struct cipher_context* ctx = (struct cipher_context*)arg;
    struct cipher* de_c = ctx->de_cipher;

    int ret = read_salt(source, de_c);
    if (ret == -2) {
        return BEV_NEED_MORE;
    } else if (ret == -1) {
        return BEV_ERROR;
    }

    size_t size = 0;
    static uint8_t plaintext[MAX_PAYLOAD_LENGTH];

    while ((size = evbuffer_get_length(source)) > 0) {
        uint8_t* data = evbuffer_pullup(source, size);
        assert(data);

        size_t plaintext_len = 0;
        int ret = aead_decrypt(de_c, data, size, plaintext, &plaintext_len);
        if (ret == 0) {
            size_t ciphertext_len = 2 + plaintext_len + 2 * de_c->tag_size;
            evbuffer_drain(source, ciphertext_len);
            evbuffer_add(destination, plaintext, plaintext_len);
        } else if (ret == -2) {
            return BEV_NEED_MORE;
        } else if (ret == -1) {
            return BEV_ERROR;
        }
    }

    return BEV_OK;
}

static enum bufferevent_filter_result
encrypt_filter_cb(struct evbuffer* source, struct evbuffer* destination, ev_ssize_t dst_limit,
                  enum bufferevent_flush_mode mode, void* arg) {
    assert(dst_limit == -1);
    struct cipher_context* ctx = (struct cipher_context*)arg;
    struct cipher* en_c = ctx->en_cipher;

    write_salt(destination, en_c);

    static uint8_t ciphertext[2 + MAX_PAYLOAD_LENGTH + 2 * MAX_TAG_LENGTH];
    size_t size = 0;

    while ((size = evbuffer_get_length(source)) > 0) {
        uint8_t* data = evbuffer_pullup(source, size);
        assert(data);
        size_t plaintext_len = size;
        if (plaintext_len > MAX_PAYLOAD_LENGTH) {
            plaintext_len = MAX_PAYLOAD_LENGTH;
        }

        size_t ciphertext_len = 0;
        if (aead_encrypt(en_c, data, plaintext_len, ciphertext, &ciphertext_len) != 0) {
            return BEV_ERROR;
        }

        evbuffer_drain(source, plaintext_len);
        evbuffer_add(destination, ciphertext, ciphertext_len);

        size -= plaintext_len;
    }

    return BEV_OK;
}

int aead_encrypt(struct cipher* c, const uint8_t* plaintext, size_t plaintext_len,
                 uint8_t* ciphertext, size_t* ciphertext_len) {
    switch (c->method) {
    case AEAD_CHACHA20_POLY1305:
        return AEAD_CHACHA20_POLY1305_encrypt(c, plaintext, plaintext_len, ciphertext,
                                              ciphertext_len);
    default:
        break;
    }

    return -1;
}

int aead_decrypt(struct cipher* c, const uint8_t* ciphertext, size_t ciphertext_len,
                 uint8_t* plaintext, size_t* plaintext_len) {
    switch (c->method) {
    case AEAD_CHACHA20_POLY1305:
        return AEAD_CHACHA20_POLY1305_decrypt(c, ciphertext, ciphertext_len, plaintext,
                                              plaintext_len);
    default:
        break;
    }

    return -1;
}

struct bufferevent* create_encrypted_bev(struct bufferevent* bev, struct cipher_context* c) {
    return bufferevent_filter_new(bev, decrypt_filter_cb, encrypt_filter_cb, BEV_OPT_CLOSE_ON_FREE,
                                  free_cipher_context, c);
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
