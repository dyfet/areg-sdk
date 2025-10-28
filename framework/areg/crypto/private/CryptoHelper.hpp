/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/CryptoHelper.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Crypto helper functions for backend glueing and secure arrays
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_CRYPTOHELPER_HPP
#define AREG_CRYPTO_PRIVATE_CRYPTOHELPER_HPP

#if AREG_CRYPTO
#include "areg/base/GEGlobal.h"

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>

namespace NECrypto {
constexpr auto ToByte(std::byte b) noexcept {
    return static_cast<uint8_t>(b);
}

constexpr auto ToByte(uint8_t u) noexcept {
    return static_cast<std::byte>(u);
}

constexpr auto ToByte(char u) noexcept {
    return static_cast<std::byte>(u);
}

static inline auto ToBytes(const uint8_t *data) noexcept {
    return reinterpret_cast<const std::byte *>(data);
}

static inline auto ToBytes(uint8_t *data) noexcept {
    return reinterpret_cast<std::byte *>(data);
}

static inline auto ToBytes(const char *data) noexcept {
    return reinterpret_cast<const uint8_t *>(data);
}

static inline auto ToBytes(char *data) noexcept {
    return reinterpret_cast<uint8_t *>(data);
}

static inline auto ToBytes(const std::byte *data) noexcept {
    return reinterpret_cast<const uint8_t *>(data);
}

static inline auto ToBytes(std::byte *data) noexcept {
    return reinterpret_cast<uint8_t *>(data);
}

auto EncodeHex(std::string_view input) noexcept -> std::string;

template <typename T>
inline auto ToStringView(const T& obj) -> std::string_view {
    return std::string_view(reinterpret_cast<const char *>(obj.data()), obj.size
());
}

template <typename Binary>
inline auto ToHex(const Binary& bin) {
    return EncodeHex(ToStringView(bin));
}
} // end namespace
#endif
#endif

