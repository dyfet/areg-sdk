/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/MCRandom.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Generate cryptographic random values
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_MCRANDOM_HPP
#define AREG_CRYPTO_PRIVATE_MCRANDOM_HPP

#if AREG_CRYPTO

#include <cstddef>
#include <cstdint>
#ifdef _MSC_VER
#include <BaseTsd.h>
#else
#include <unistd.h>
#endif

#if defined(_WIN32) || defined (_MSC_VER)
#include <windows.h>
#include <wincrypt.h>
#endif

namespace MiniCrypt {
#ifdef _MSC_VER
using ssize_t = SSIZE_T;
#endif

struct random_ctx {
#if defined(_WIN32) || defined(_MSC_VER)
    HCRYPTPROV handle;
#else
    int fd;
#endif
};

int random_init(random_ctx& ctx);
void random_free(random_ctx& ctx);
ssize_t random_fill(random_ctx& ctx, uint8_t *buf, std::size_t size);
uint64_t uniform_random(random_ctx& ctx, uint64_t min, uint64_t max);
ssize_t make_random(void *data, std::size_t size);
} // end namespace
#endif
#endif
