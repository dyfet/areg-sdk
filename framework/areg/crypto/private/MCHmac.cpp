/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/MCHmac.cpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Message digest functions
 ************************************************************************/

#if AREG_CRYPTO

#include "areg/crypto/private/MCHmac.hpp"
#include "areg/crypto/private/MCHelper.hpp"
#include <cstring>

#define SALT_SIZE 16

namespace {
void sha256_normalize_key(const uint8_t *key, std::size_t keysize, uint8_t *out) {
    if (keysize > MiniCrypt::SHA256_BLOCK_SIZE) {
        MiniCrypt::sha256_ctx key_ctx;
        MiniCrypt::sha256_init(key_ctx);
        MiniCrypt::sha256_update(key_ctx, key, keysize);
        MiniCrypt::sha256_final(key_ctx, out); // 32 bytes
        MiniCrypt::memset(out + 32, 0, MiniCrypt::SHA256_BLOCK_SIZE - 32);
    } else {
        MiniCrypt::memcpy(out, key, keysize);
        MiniCrypt::memset(out + keysize, 0, MiniCrypt::SHA256_BLOCK_SIZE - keysize);
    }
}
}

void MiniCrypt::hmac256(const uint8_t *key, std::size_t keysize, const uint8_t *data, std::size_t size, uint8_t *out) {
    uint8_t keyblock[SHA256_BLOCK_SIZE];
    uint8_t ipad[SHA256_BLOCK_SIZE];
    uint8_t opad[SHA256_BLOCK_SIZE];
    sha256_normalize_key(key, keysize, keyblock);
    for (std::size_t i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        ipad[i] = keyblock[i] ^ 0x36;
        opad[i] = keyblock[i] ^ 0x5c;
    }

    sha256_ctx inner;
    sha256_init(inner);
    sha256_update(inner, ipad, SHA256_BLOCK_SIZE);
    sha256_update(inner, data, size);
    uint8_t inner_digest[32];
    sha256_final(inner, inner_digest);

    sha256_ctx outer;
    sha256_init(outer);
    sha256_update(outer, opad, SHA256_BLOCK_SIZE);
    sha256_update(outer, inner_digest, 32);
    sha256_final(outer, out);
}

void MiniCrypt::pbkdf2(const uint8_t *pass, std::size_t len, const uint8_t *salt, uint32_t rounds, uint8_t *out, std::size_t size) {
    uint32_t block_count = (size + 31) / 32;
    uint8_t U[32], T[32];
    uint8_t salt_block[SALT_SIZE + 4];
    for (std::size_t i = 1; i <= block_count; ++i) {
        MiniCrypt::memcpy(salt_block, salt, SALT_SIZE);
        salt_block[SALT_SIZE + 0] = (i >> 24) & 0xff;
        salt_block[SALT_SIZE + 1] = (i >> 16) & 0xff;
        salt_block[SALT_SIZE + 2] = (i >> 8) & 0xff;
        salt_block[SALT_SIZE + 3] = i & 0xff;
        hmac256(pass, len, salt_block, SALT_SIZE + 4, U);
        MiniCrypt::memcpy(T, U, 32);
        for (uint32_t j = 1; j < rounds; ++j) {
            hmac256(pass, len, U, 32, U);
            for (int k = 0; k < 32; ++k)
                T[k] ^= U[k];
        }

        std::size_t offset = (i - 1) * 32;
        std::size_t copy = (offset + 32 > size) ? size - offset : 32;
        MiniCrypt::memcpy(out + offset, T, copy);
    }
}

#endif
