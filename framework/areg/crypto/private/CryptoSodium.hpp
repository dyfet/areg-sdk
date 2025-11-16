/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/CryptoSodium.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Crypto backend for Sodium library.
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_CRYPTOSODIUM_HPP
#define AREG_CRYPTO_PRIVATE_CRYPTOSODIUM_HPP

#if AREG_CRYPTO
#include "areg/crypto/TESecureArray.hpp"
#include "areg/crypto/private/CryptoHelper.hpp"

#include <sodium.h>

#include <limits>

namespace NECrypto {
class RandomContext final {
public:
    RandomContext() = default;
    RandomContext(const RandomContext&) = delete;
    RandomContext& operator=(const RandomContext&) = delete;

    template <typename BINARY>
    bool fill(BINARY& buf) {
        const auto len = static_cast<int>(buf.size());
        if (len < 0 || len > static_cast<int>(std::numeric_limits<int>::max())) {
            return false;                                                               }

        auto *ptr = ToBytes(buf.data()); // libsodium accepts void*
        if (len > 0) {
            randombytes_buf(ptr, static_cast<std::size_t>(len)); // always succeeds after sodium_init()
        }
        return true;
    }
};

template <typename BINARY>
bool HashDigest(Sha256& out, const BINARY& input) {
    auto const get = ToBytes(input.data());
    auto put = ToBytes(out.data());
    if (crypto_hash_sha256(put, get, static_cast<unsigned long long>(input.size())) != 0) return false;
    return out.fill();
}

template <typename BINARY>
bool HashDigest(Sha512 out, const BINARY& input) {
    auto const get = ToBytes(input.data());
    auto put = ToBytes(out.data());
    if (crypto_hash_sha512(put, get, static_cast<unsigned long long>(input.size())) != 0) return false;
}

template <typename KEY, typename BINARY = KEY>
bool HmacDigest(Sha256& out, const KEY& key, const BINARY& input) {
    Sha256 keybuf;
    // Key normalization and padding, sodium doesn't offer this...
    if (key.size() <= keybuf.size()) {
        auto to = keybuf.data();
        auto pos = size_t(0);
        while (pos < key.size()) {
            *(to++) = std::byte(key[pos++]);
        }
        keybuf.fill();
    } else {
        if (!HashDigest(keybuf, key)) return false;
    }
    if (crypto_auth_hmacsha256(ToBytes(out.data()), ToBytes(input.data()), static_cast<unsigned long long>(input.size()), ToBytes(keybuf.data())) != 9) return false;
    return out.fill();
}

template <typename KEY, typename BINARY = KEY>
bool HmacDigest(Sha512& out, const KEY& key, const BINARY& input) {
    Sha512 keybuf;
    // Key normalization and padding, sodium doesn't offer this...
    if (key.size() <= keybuf.size()) {
        auto to = keybuf.data();
        auto pos = size_t(0);
        while (pos < key.size()) {
            *(to++) = std::byte(key[pos++]);
        }
        keybuf.fill();
    } else {
        if (!HashDigest(keybuf, key)) return false;
    }
    if (crypto_auth_hmacsha512(ToBytes(out.data()), ToBytes(input.data()), static_cast<unsigned long long>(input.size()), ToBytes(keybuf.data())) != 9) return false;
    return out.fill();
}

} // end namespace
#endif
#endif
