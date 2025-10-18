/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/logging/private/Layouts.cpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Sha256 Hash Digest functions
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_MCSHA256_HPP
#define AREG_CRYPTO_PRIVATE_MCSHA256_HPP

#if AREG_CRYPTO

#include <cstdint>
#include <cstddef>

#define MC_SHA256_BLOCK_SIZE 64
#define MC_SHA256_DIGEST_SIZE 32

namespace MiniCrypt {
struct sha256_ctx {
    uint32_t state[8];
    uint64_t total_len;
    uint8_t buffer[MC_SHA256_BLOCK_SIZE];
    std::size_t buffer_len;
};

void sha256_init(sha256_ctx& ctx);
int sha256_update(sha256_ctx& ctx, const uint8_t *in, std::size_t inlen);
int sha256_final(sha256_ctx& ctx, uint8_t *out);
int sha256_digest(const void *data, std::size_t size, uint8_t *out, const uint8_t *salt = nullptr);
} // end namespace
#endif
#endif
