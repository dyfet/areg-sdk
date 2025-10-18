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
 * \brief       Sha1 Hash Digest functions
 ************************************************************************/

#if AREG_CRYPTO

#include "MCSha1.hpp"
#include "MCHelper.hpp"
#include <cstring>

namespace {
uint32_t load_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

void store_be32(uint8_t *p, uint32_t x) {
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)(x);
}

const uint32_t sha1_initial_state[5] = {
0x67452301, 0xEFCDAB89,
0x98BADCFE, 0x10325476,
0xC3D2E1F0};

const uint32_t K[4] = {
0x5A827999, // rounds 0–19
0x6ED9EBA1, // rounds 20–39
0x8F1BBCDC, // rounds 40–59
0xCA62C1D6  // rounds 60–79
};

inline uint32_t rotl(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

void sha1_compress(MiniCrypt::sha1_ctx& ctx, const uint8_t block[64]) {
    uint32_t w[80];
    uint32_t a, b, c, d, e;

    for (int i = 0; i < 16; ++i) {
        w[i] = load_be32(block + ((ptrdiff_t)i * 4));
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = ctx.state[0];
    b = ctx.state[1];
    c = ctx.state[2];
    d = ctx.state[3];
    e = ctx.state[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = K[0];
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = K[1];
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = K[2];
        } else {
            f = b ^ c ^ d;
            k = K[3];
        }

        uint32_t temp = rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = temp;
    }

    ctx.state[0] += a;
    ctx.state[1] += b;
    ctx.state[2] += c;
    ctx.state[3] += d;
    ctx.state[4] += e;
    MiniCrypt::memset(w, 0, sizeof(w));
}
} // emd namespace

void MiniCrypt::sha1_init(sha1_ctx& ctx) {
    MiniCrypt::memcpy(ctx.state, sha1_initial_state, sizeof(sha1_initial_state));
    ctx.total_len = 0;
    ctx.buffer_len = 0;
}

int MiniCrypt::sha1_update(sha1_ctx& ctx, const uint8_t *data, std::size_t len) {
    ctx.total_len += len;
    std::size_t offset = 0;
    while (len > 0) {
        std::size_t space = SHA1_BLOCK_SIZE - ctx.buffer_len;
        std::size_t to_copy = (len < space) ? len : space;
        MiniCrypt::memcpy(ctx.buffer + ctx.buffer_len, data + offset, to_copy);
        ctx.buffer_len += to_copy;
        offset += to_copy;
        len -= to_copy;
        if (ctx.buffer_len == SHA1_BLOCK_SIZE) {
            sha1_compress(ctx, ctx.buffer);
            ctx.buffer_len = 0;
        }
    }
    return 0;
}

int MiniCrypt::sha1_final(sha1_ctx& ctx, uint8_t *out) {
    uint8_t pad[SHA1_BLOCK_SIZE + 8] = {0};
    uint64_t bit_len = ctx.total_len * 8;
    pad[0] = 0x80;
    std::size_t rem = ctx.buffer_len;
    std::size_t pad_len = (rem < 56) ? (56 - rem) : (SHA1_BLOCK_SIZE + 56 - rem);
    for (int i = 0; i < 8; ++i) {
        pad[pad_len + i] = (uint8_t)(bit_len >> (56 - 8 * i));
    }

    MiniCrypt::sha1_update(ctx, pad, pad_len + 8);
    for (int i = 0; i < 5; ++i) {
        store_be32(out + ((ptrdiff_t)i * 4), ctx.state[i]);
    }

    MiniCrypt::memset(&ctx, 0, sizeof(MiniCrypt::sha1_ctx));
    return 0;
}

int MiniCrypt::sha1_digest(const void *data, std::size_t size, uint8_t *out, const uint8_t *salt) {
    sha1_ctx ctx;
    sha1_init(ctx);
    if (salt)
        sha1_update(ctx, salt, 16);
    sha1_update(ctx, reinterpret_cast<const uint8_t *>(data), size);
    return sha1_final(ctx, out);
}

#endif
