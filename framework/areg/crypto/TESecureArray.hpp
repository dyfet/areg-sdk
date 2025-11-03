/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/TESecureArray.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Secure array template. no heap, clears on destruction
 ************************************************************************/

#ifndef AREG_CRYPTO_TESECUREARRAY_HPP
#define AREG_CRYPTO_TESECUREARRAY_HPP

#if AREG_CRYPTO

#include "areg/crypto/private/MCHelper.hpp"

namespace NECrypto {
template <std::size_t SIZE>
class TESecureArray final {
public:
    TESecureArray() noexcept = default;
    TESecureArray(const TESecureArray& from) noexcept : _empty(from._empty) {
        if (!_empty)
            MiniCrypt::memcpy(_data, from._data, SIZE);
    }

    ~TESecureArray() noexcept {
        _erase();
    }

    auto operator=(const TESecureArray& from) noexcept -> auto& {
        if (this == &from) return *this;
        MiniCrypt::memcpy(_data, from._data, SIZE);
        _empty = from._empty;
        return *this;
    }

    auto operator==(const TESecureArray& other) const noexcept {
        if (other._empty != _empty) return false;
        return memcmp(_data, other._data, SIZE) == 0;
    }

    auto operator!=(const TESecureArray& other) const noexcept {
        if (other._empty != _empty) return true;
        return memcmp(_data, other._data, SIZE) != 0;
    }

    auto operator^=(const TESecureArray& other) noexcept -> TESecureArray& {
        for (unsigned pos = 0; pos < SIZE; ++pos) {
            _data[pos] ^= other._data[pos];
        }
        return *this;
    }

    auto operator&=(const TESecureArray& other) noexcept -> TESecureArray& {
        for (unsigned pos = 0; pos < SIZE; ++pos) {
            _data[pos] &= other._data[pos];
        }
        return *this;
    }

    auto operator|=(const TESecureArray& other) noexcept -> TESecureArray& {
        for (unsigned pos = 0; pos < SIZE; ++pos) {
            _data[pos] |= other._data[pos];
        }
        return *this;
    }

    auto toBytes() noexcept {
        return reinterpret_cast<uint8_t *>(&_data);
    }

    auto toBytes() const noexcept {
        return reinterpret_cast<const uint8_t *>(&_data);
    }

    auto toHex() const noexcept -> std::string {
        constexpr char hex[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(SIZE * 2);
        std::size_t pos{0};
        while (pos < SIZE) {
            auto val = uint8_t(_data[pos++]);
            out.push_back(hex[val >> 4]);
            out.push_back(hex[val & 0x0f]);
        }
        return out;
    }

    // memory safe copy so we can remove [] operators
    template <typename BINARY>
    auto copy(std::size_t offset, const BINARY& from) -> std::size_t {
        if (offset >= SIZE || from.size() < 1) return 0;
        std::size_t count = from.size();
        if (count + offset > SIZE)
            count = SIZE - offset;
        MiniCrypt::memcpy(_data, from.data(), count);
        return count;
    }

    // Used to help fill routines mark if successfully filling
    auto fill(bool flag = true) noexcept {
        if (flag) _empty = false;
        return flag;
    }

    // Used to mark array as cleared / has stale data
    void clear() noexcept {
        if (!_empty) _erase();
        _empty = true;
    }

    // These provide standard duck type methods and bindings like std::
    constexpr operator bool() const noexcept { return !_empty; }
    constexpr auto operator!() const noexcept { return _empty; }
    constexpr auto data() const noexcept -> const std::byte * { return _data; };
    constexpr auto data() noexcept -> std::byte * { return _data; };
    constexpr auto size() const noexcept { return SIZE; };
    constexpr auto empty() const noexcept { return _empty; }

private:
    static_assert(SIZE > 0, "Secure data size invalid");
    std::byte _data[SIZE]{};
    bool _empty{true};

    void _erase() noexcept {
        MiniCrypt::memset(data(), 0, SIZE);
    }
};
} // end namespace
#endif
#endif

