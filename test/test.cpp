#include <stdlib.h>

#include <gtest/gtest.h>
#include <sodium.h>

#include "../aead.h"
#include "../crypto.h"

GTEST_TEST(KDF, derive_key) {
    const char* password = "hehe";

    unsigned char key[32];
    unsigned char expect_key[32] = {82,  156, 168, 5,   10,  0,   24,  7,   144, 207, 136,
                                    182, 52,  104, 130, 106, 109, 81,  225, 207, 24,  87,
                                    148, 16,  101, 57,  172, 239, 219, 100, 183, 95};
    derive_key(password, key, sizeof key);

    ASSERT_TRUE(memcmp(key, expect_key, 32) == 0);
}

GTEST_TEST(AEAD, AEAD_CHACHA20_POLY1305_HKDF_SHA1) {
    unsigned char key[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    unsigned char subkey[32];

    unsigned char expect_subkey[32] = {128, 145, 113, 44,  108, 52, 99,  117, 243, 229, 199,
                                       245, 55,  99,  251, 53,  56, 225, 92,  92,  5,   94,
                                       252, 21,  4,   211, 164, 43, 251, 44,  61,  208};

    AEAD_CHACHA20_POLY1305_HKDF_SHA1(key, (const unsigned char*)"12345678123456781234567812345678",
                                     subkey);

    ASSERT_TRUE(memcmp(subkey, expect_subkey, 32) == 0);
}

GTEST_TEST(AEAD, AEAD_CHACHA20_POLY1305) {
    ASSERT_TRUE(sodium_init() == 0);

    unsigned char key[32] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                             1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};

#define DATA_SIZE 5
    unsigned char data[DATA_SIZE] = {'h', 'e', 'l', 'l', 'o'};
    unsigned char ciphertext[2 + 16 + DATA_SIZE + 16];
    unsigned char plaintext[DATA_SIZE];

    struct cipher* en_c = alloc_cipher(AEAD_CHACHA20_POLY1305, NULL);
    memcpy(en_c->key, key, en_c->key_size);
    struct cipher* de_c = alloc_cipher(AEAD_CHACHA20_POLY1305, NULL);
    memcpy(de_c->key, key, de_c->key_size);

    randombytes_buf(en_c->salt, en_c->salt_size);
    memcpy(de_c->salt, en_c->salt, en_c->salt_size);

    ASSERT_TRUE(aead_encrypt(en_c, data, DATA_SIZE, ciphertext) == 0);
    ASSERT_TRUE(aead_decrypt(de_c, ciphertext, sizeof ciphertext, plaintext) >= 0);

    ASSERT_TRUE(memcmp(data, plaintext, DATA_SIZE) == 0);
}
