/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/Crypto.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Selects crypto backnd and provides basic types, common code
 ************************************************************************/

#ifndef AREG_CRYPTO_CRYPTO_HPP
#define AREG_CRYPTO_CRYPTO_HPP

#if AREG_CRYPTO

#include "areg/crypto/TESecureArray.hpp"
#include "areg/crypto/private/CryptoHelper.hpp"

namespace NECrypto {
using Salt = TESecureArray<8>;
using Sha256 = TESecureArray<32>;
using Sha512 = TESecureArray<64>;
}

// Selects backend header library based on defines...
#if AREG_CRYPTO_OPENSSL
#include "areg/crypto/private/CeyptoOpenssl.hpp"
#elif AREG_CRYPTO_SODIUM
#include "areg/crypto/private/CeyptoSodium.hpp"
#else
#include "areg/crypto/private/CryptoMinicrypt.hpp"
#endif

// common functionms that depend on a backend...

namespace NECrypto {
template <std::size_t S>
auto RandomKey(TESecureArray<S>& key) {
    RandomContext rng;
    return key.fill(rng.fill(key));
}

template <typename KEY>
bool RandomKey(KEY& key) {
    RandomContext rng;
    key.clear();
    return key.fill(rng.fill(key));
}

Salt MakeSalt() {
    Salt salt;
    RandomContext rng;
    salt.fill(rng.fill(salt));
    return salt;
}

template <typename BINARY, typename DIGEST = Sha256>
uint64_t ToU64(const BINARY& input) {
    DIGEST digest;
    static_assert(digest.size() >= sizeof(uint64_t));
    if (!init_digest(digest, input)) return static_cast<uint64_t>(-1);
    uint64_t out{0};
    const auto bin = digest.ToBytes();
    for (std::size_t i = 0; i < sizeof(out); ++i) {
        out = (out << 8) | static_cast<uint8_t>(bin[i]);
    }
    return out;
}
}

#endif
#endif

