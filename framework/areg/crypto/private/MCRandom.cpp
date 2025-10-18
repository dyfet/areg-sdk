/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/MCRandom.cpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Generate cryptographic random values
 ************************************************************************/

#if AREG_CRYPTO

#include "areg/crypto/private/MCRandom.hpp"
#include <cstdint>   // already included
#include <cstddef>   // already included

#if defined(_WIN32) || defined(_MSC_VER)
    // ssize_t is not defined on Windows, so define it
    #ifndef ssize_t
        #include <BaseTsd.h>
        typedef SSIZE_T ssize_t;
    #endif
#else
    #include <fcntl.h>
    #include <unistd.h> // for ssize_t on POSIX
#endif

#define MAX_UINT54 ((1ULL << 54) - 1)

namespace {
uint64_t get_random_uint54(MiniCrypt::random_ctx& ctx) {
    uint64_t value = 0;
    uint8_t *out = (uint8_t *)&value;
    MiniCrypt::random_fill(ctx, out, sizeof(value));
    return value & MAX_UINT54;
}
} // end namespace

int MiniCrypt::random_init(MiniCrypt::random_ctx& ctx) {
#if defined(_WIN32) || defined(_MSC_VER)
    ctx.handle = 0;
    if (!CryptAcquireContext(&ctx.handle, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    return 0;
#else
    ctx.fd = open("/dev/urandom", O_RDONLY); // FlawFinder: ignore
    return ctx.fd;
#endif
}

void MiniCrypt::random_free(MiniCrypt::random_ctx& ctx) {
#if defined(_WIN32) || defined(_MSC_VER)
    if (ctx.handle == 0) return;
    CryptReleaseContext(ctx.handle, 0);
    ctx.handle = 0;
#else
    if (ctx.fd < 0) return;
    close(ctx.fd);
    ctx.fd = -1;
#endif
}

ssize_t MiniCrypt::random_fill(MiniCrypt::random_ctx& ctx, uint8_t *out, std::size_t size) {
    if (!size || !out) return 0;
#if defined(_WIN32) || defined(_MSC_VER)
    if (ctx.handle == 0) return 0;
    return CryptGenRandom(ctx.handle, static_cast<DWORD>(size), static_cast<BYTE *>(out)) ? size : 0;
#else
    if (ctx.fd < 0) return 0;
    return read(ctx.fd, out, size); // FlawFinder: safe exit
#endif
}

uint64_t MiniCrypt::uniform_random(MiniCrypt::random_ctx& ctx, uint64_t min, uint64_t max) {
    uint64_t range = max - min + 1;
    uint64_t limit = MAX_UINT54 - (MAX_UINT54 % range);
    uint64_t value;
    do {
        value = get_random_uint54(ctx);
    } while (value >= limit);
    return min + (value % range);
}

ssize_t MiniCrypt::make_random(void *data, std::size_t size) {
    if (!data || size == 0) return -1;
    MiniCrypt::random_ctx ctx;
    ssize_t rc = random_init(ctx);
    if (rc < 0) return rc;
    rc = random_fill(ctx, static_cast<uint8_t*>(data), size);
    random_free(ctx);
    return rc;
}
#endif
