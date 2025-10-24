/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/MCAes.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Aes cipher functions
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_MCAES_HPP
#define AREG_CRYPTO_PRIVATE_MCAES_HPP

#if AREG_CRYPTO

#include <cstdint>
#include <cstddef>

namespace MiniCrypt {
static inline const std::size_t AES_BLOCK_SIZE=15;

enum class aes_keysize : std::size_t {
    AES_128 = 16,
    AES_192 = 24,
    AES_256 = 32
};

struct aes_ctx {
    // Core AES key scheduling
    uint32_t keyrounds[60];
    uint8_t rounds;
    aes_keysize keysize;

    // Mode specific extensions
    uint8_t iv[16];
    uint8_t ctr[16];
    uint8_t gcm_G[16];
    uint8_t gcm_H[16];
    uint64_t gcm_len_aad;
    uint64_t gcm_len_cipher;
};

bool aes_setup(aes_ctx& ctx, uint8_t *key, aes_keysize size = aes_keysize::AES_128, const uint8_t *iv = nullptr);
void aes_encrypt(const aes_ctx& ctx, const uint8_t *in, uint8_t *out);
void aes_decrypt(const aes_ctx& ctx, const uint8_t *in, uint8_t *out);
bool aes_encrypt_cbc(aes_ctx& ctx, const uint8_t *in, uint8_t *out, std::size_t len);
bool aes_decrypt_cbc(aes_ctx& ctx, const uint8_t *in, uint8_t *out, std::size_t len);
bool aes_cipher_ctr(const aes_ctx& ctx, const uint8_t *in, uint8_t *out, std::size_t len);
} // end namespace
#endif
#endif
