/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/MCSha1.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Sha1 Hash Digest functions
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_MCSHA1_HPP
#define AREG_CRYPTO_PRIVATE_MCSHA1_HPP

#if AREG_CRYPTO
#include <cstdint>
#include <cstddef>

namespace MiniCrypt {
static inline const std::size_t SHA1_BLOCK_SIZE = 64;
static inline const std::size_t SHA1_DIGEST_SIZE = 20;

struct sha1_ctx {
    uint32_t state[5];
    uint64_t total_len;
    uint8_t buffer[SHA1_BLOCK_SIZE];
    std::size_t buffer_len;
};

void sha1_init(sha1_ctx& ctx);
int sha1_update(sha1_ctx& ctx, const uint8_t *in, std::size_t inlen);
int sha1_final(sha1_ctx& ctx, uint8_t *out);
int sha1_digest(const void *data, std::size_t size, uint8_t *out, const uint8_t *salt = nullptr);
} // end namespace
#endif
#endif
