/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/CryptoMinicrypt.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Crypto backend for Minicrypt operations
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_CRYPTOMINICRYPT_HPP
#define AREG_CRYPTO_PRIVATE_CRYPTOMINICRYPT_HPP

#if AREG_CRYPTO
#include "areg/crypto/TESecureArray.hpp"
#include "areg/crypto/private/CryptoHelper.hpp"
#include "areg/crypto/private/MCHelper.hpp"
#include "areg/crypto/private/MCSha256.hpp"
#include "areg/crypto/private/MCRandom.hpp"
#include "areg/crypto/private/MCHmac.hpp"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

namespace NECrypto {
class RandomContext final {
public:
    RandomContext() { MiniCrypt::random_init(_rng); }
    ~RandomContext() { MiniCrypt::random_free(_rng); }
    RandomContext(const RandomContext&) = delete;
    RandomContext& operator=(const RandomContext&) = delete;

    template <typename BINARY>
    inline bool fill(BINARY& buf) {
        auto const put = ToBytes(buf.data());
        auto len = MiniCrypt::random_fill(_rng, put, buf.size());
        return len == ssize_t(buf.size());
    }

private:
    MiniCrypt::random_ctx _rng;
};

template <typename BINARY>
bool HashDigest(Sha256& out, const BINARY& input, Salt& salt = Salt()) {
    MiniCrypt::sha256_ctx ctx;
    auto const get = ToBytes(input.data());
    auto const sp = ToBytes(salt.data());
    auto put = ToBytes(out.data());
    MiniCrypt::sha256_init(ctx);
    if (!salt.empty()) MiniCrypt::sha256_update(ctx, sp, salt.size());
    MiniCrypt::sha256_update(ctx, get, input.size());
    MiniCrypt::sha256_final(ctx, put);
    return out.fill();
}

template <typename KEY, typename BINARY = KEY>
bool HmacDigest(Sha256& out, const KEY& key, const BINARY& input) {
    auto const get = ToBytes(input.data());
    auto const kv = ToBytes(key.data());
    auto put = ToBytes(out.data());
    MiniCrypt::hmac256(kv, key.size(), get, input.size(), put);
    return out.fill();
}
} // end namespace
#endif
#endif
