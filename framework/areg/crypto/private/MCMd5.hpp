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
 * \brief       MD5 MD5 Digest functions
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_MCMD5_HPP
#define AREG_CRYPTO_PRIVATE_MCMD5_HPP

#if AREG_CRYPTO
#include <cstdint>
#include <cstddef>

namespace MiniCrypt {
static inline const std::size_t MD5_BLOCK_SIZE = 64;
static inline const std::size_t MD5_DIGEST_SIZE = 16;

struct md5_ctx {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[MD5_BLOCK_SIZE];
};

void md5_init(md5_ctx& ctx);
int md5_update(md5_ctx& ctx, const uint8_t *input, uint32_t size);
int md5_final(md5_ctx& ctx, uint8_t *out);
int md5_digest(const void *data, std::size_t size, uint8_t *out, const uint8_t *salt = nullptr);

} // end namespace
#endif
#endif
