/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/CryptoOpenssl.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Crypto backend for OpenSSL
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_CRYPTOOOPENSSL_HPP
#define AREG_CRYPTO_PRIVATE_CRYPTOOOPENSSL_HPP

#if AREG_CRYPTO
#include "areg/crypto/TESecureArray.hpp"
#include "areg/crypto/private/CryptoHelper.hpp"

#include <limits>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

namespace NECrypto {
class RandomContext final {
public:
    RandomContext() = default;
    RandomContext(const RandomContext&) = delete;
    RandomContext& operator=(const RandomContext&) = delete;

    template <typename BINARY>
    inline bool fill(BINARY& buf) {
        const auto len = static_cast<int>(buf.size());
        if (len < 0 || len > std::numeric_limits<int>::max()) return false;
        auto *ptr = ToBytes(buf.data());
        return RAND_bytes(ptr, len) == 1;
    }
};

template <typename BINARY>
bool HashDigest(Sha256& out, const BINARY& input) {
    constexpr std::size_t sha_size = 32;
    unsigned int out_len = 0;
    auto get = ToBytes(input.data());

    if (!EVP_Digest(get, input.size(), out.toBytes(), &out_len, EVP_sha256(), nullptr)) return false;
    if (out_len != sha_size) return false;
    return out.fill();
}

template <typename BINARY>
bool HashDigest(Sha512 out, const BINARY& input) {
    constexpr std::size_t sha_size = 64;
    unsigned int out_len = 0;
    auto get = ToBytes(input.data());

    if (!EVP_Digest(get, input.size(), out.toBytes(), &out_len, EVP_sha512(), nullptr)) return false;
    if (out_len != sha_size) return false;
    return out.fill();
}

template <typename KEY, typename BINARY = KEY>
bool HmacDigest(Sha256& out, const KEY& key, const BINARY& input) {
    constexpr std::size_t sha_size = 32;
    unsigned int out_len = 0;
    auto kp = ToBytes(key.data());
    auto ip = ToBytes(input.data());
    if (!HMAC(EVP_sha256(), kp, key.size(), ip, input.size(), out.toBytes(), &out_len)) return false;
    if (out_len != sha_size) return false;
    return out.fill();
}

template <typename KEY, typename BINARY = KEY>
bool HmacDigest(Sha512& out, const KEY& key, const BINARY& input) {
    constexpr std::size_t sha_size = 64;
    unsigned int out_len = 0;
    auto kp = ToBytes(key.data());
    auto ip = ToBytes(input.data());
    if (!HMAC(EVP_sha512(), kp, key.size(), ip, input.size(), out.toBytes(), &out_len)) return false;
    if (out_len != sha_size) return false;
    return out.fill();
}
} // end namespace
#endif
#endif
