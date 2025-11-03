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

#include "areg/base/NEMath.hpp"
#include "areg/base/NEMemory.hpp"
#include "areg/crypto/private/MCHelper.hpp"

//////////////////////////////////////////////////////////////////////////
// EventData class declaration
//////////////////////////////////////////////////////////////////////////
/**
 * \brief   TESecureArray class, used to hold secure data in stack memory.
 **/
template <std::size_t SIZE>
class TESecureArray final
{
    static_assert(SIZE > 0, "Secure data size invalid");

//////////////////////////////////////////////////////////////////////////
// Constructors / Destructor
//////////////////////////////////////////////////////////////////////////
public:
    TESecureArray() noexcept = default;
    TESecureArray(const TESecureArray<SIZE>& from) noexcept;

    // Load a key value from a physical address object
    TESecureArray(const std::byte* from) noexcept;

    // Adapts other binary types like std::string[_view}, spans, etc...
    template <typename BINARY>
    explicit TESecureArray(const BINARY& from) noexcept;

    ~TESecureArray() noexcept;

//////////////////////////////////////////////////////////////////////////
// operators
//////////////////////////////////////////////////////////////////////////
public:
    TESecureArray<SIZE>& operator = (const TESecureArray<SIZE>& from) noexcept;

    TESecureArray<SIZE>& operator=(const std::byte* from) noexcept;

    template <typename BINARY>
    TESecureArray<SIZE>& operator = (const BINARY& from) noexcept;

    bool operator == (const TESecureArray<SIZE>& other) const noexcept;

    bool operator != (const TESecureArray<SIZE>& other) const noexcept;

    TESecureArray<SIZE>& operator ^=(const TESecureArray<SIZE>& other) noexcept;

    TESecureArray<SIZE>& operator &= (const TESecureArray<SIZE>& other) noexcept;

    TESecureArray<SIZE>& operator |= (const TESecureArray<SIZE>& other) noexcept;

    // These provide standard duck type methods and bindings like std::
    constexpr operator bool() const noexcept;

    constexpr bool operator!() const noexcept;

//////////////////////////////////////////////////////////////////////////
// Attributes
//////////////////////////////////////////////////////////////////////////
public:

    uint8_t* toBytes() noexcept;

    const uint8_t* toBytes() const noexcept;

    constexpr const std::byte* data() const noexcept;
    constexpr std::byte* data() noexcept;

    constexpr std::size_t size() const noexcept;

    constexpr bool empty() const noexcept;

//////////////////////////////////////////////////////////////////////////
// Operations
//////////////////////////////////////////////////////////////////////////
public:

    std::string toHex() const noexcept;

    // memory safe copy so we can remove [] operators
    template <typename BINARY>
    std::size_t copy(std::size_t offset, const BINARY &  from);

    // Used to help fill routines mark if successfully filling
    bool fill(bool flag = true) noexcept;

    // Used to mark array as cleared / has stale data
    void clear() noexcept;

//////////////////////////////////////////////////////////////////////////
// Hidden methods
//////////////////////////////////////////////////////////////////////////
private:

    void _erase() noexcept;

//////////////////////////////////////////////////////////////////////////
// Member variables
//////////////////////////////////////////////////////////////////////////
private:
    std::byte   mData[SIZE]{};
    bool        mIsEmpty;

};

//////////////////////////////////////////////////////////////////////////
// TESecureArray implementation
//////////////////////////////////////////////////////////////////////////

template <std::size_t SIZE>
TESecureArray<SIZE>::TESecureArray(const TESecureArray<SIZE>& from) noexcept
    : mIsEmpty(from.mIsEmpty)
{
    if (!mIsEmpty)
    {
        NEMemory::memCopy(mData, SIZE, from.mData, from.size());
    }
}

template <std::size_t SIZE>
TESecureArray<SIZE>::TESecureArray(const std::byte* from) noexcept
    : mIsEmpty  (from == nullptr)
{
    if (from != nullptr)
    {
        NEMemory::memCopy(mData, SIZE, from, SIZE);
    }
}

template <std::size_t SIZE>
template <typename BINARY>
TESecureArray<SIZE>::TESecureArray(const BINARY& from) noexcept
    : mIsEmpty(true)
{
    auto len = std::min(SIZE, from.size());
    if (len)
    {
        NEMemory::memCopy(mData, SIZE, from.data(), len);
        // forces erasure of origin data...
        auto wp = const_cast<void*>(reinterpret_cast<const void*>(from.data()));
        NEMemory::memZero(wp, from.size());
        mIsEmpty = false;
    }
}

template <std::size_t SIZE>
TESecureArray<SIZE>::~TESecureArray() noexcept
{
    _erase();
}

template <std::size_t SIZE>
TESecureArray<SIZE>& TESecureArray<SIZE>::operator = (const TESecureArray<SIZE>& from) noexcept
{
    if (this != &from)
    {
        NEMemory::memCopy(mData, SIZE, from.mData, from.size());
        mIsEmpty = from.mIsEmpty;
    }

    return *this;
}

template <std::size_t SIZE>
TESecureArray<SIZE>& TESecureArray<SIZE>::operator=(const std::byte* from) noexcept
{
    mIsEmpty = (from == nullptr);
    if (from != nullptr)
    {
        MiniCrypt::memcpy(mData, SIZE, from, SIZE);
    }

    return *this;
}

template <std::size_t SIZE>
template <typename BINARY>
TESecureArray<SIZE>& TESecureArray<SIZE>::operator = (const BINARY& from) noexcept
{
    auto len = std::min(SIZE, from.size());
    if (len)
    {
        mIsEmpty = false;
        NEMemory::memCopy(&mData, SIZE, from.data(), len);
        // Forces erasure of origin data
        const void* wp = reinterpret_cast<const void*>(from.data());
        NEMemory::memZero(const_cast<void *>(wp), from.size());
    }

    return *this;
}

template <std::size_t SIZE>
bool TESecureArray<SIZE>::operator == (const TESecureArray<SIZE>& other) const noexcept
{
    return (this == &other) || ((other.mIsEmpty == mIsEmpty) && NEMemory::memEqual(mData, other.mData, SIZE));
}

template <std::size_t SIZE>
bool TESecureArray<SIZE>::operator != (const TESecureArray<SIZE>& other) const noexcept
{
    return (this != &other) && ((other.mIsEmpty != mIsEmpty) || (NEMemory::memEqual(mData, other.mData, SIZE) == false));
}

template <std::size_t SIZE>
TESecureArray<SIZE>& TESecureArray<SIZE>::operator ^=(const TESecureArray<SIZE>& other) noexcept
{
    if (this != &other)
    {
        for (uint32_t pos = 0; pos < SIZE; ++pos)
            mData[pos] ^= other.mData[pos];
    }

    return *this;
}

template <std::size_t SIZE>
TESecureArray<SIZE>& TESecureArray<SIZE>::operator &= (const TESecureArray<SIZE>& other) noexcept
{
    if (this != &other)
    {
        for (uint32_t pos = 0; pos < SIZE; ++pos)
            mData[pos] &= other.mData[pos];
    }

    return *this;
}

template <std::size_t SIZE>
TESecureArray<SIZE>& TESecureArray<SIZE>::operator |= (const TESecureArray<SIZE>& other) noexcept
{
    if (this != &other)
    {
        for (uint32_t pos = 0; pos < SIZE; ++pos)
            mData[pos] |= other.mData[pos];
    }

    return *this;
}

template <std::size_t SIZE>
uint8_t* TESecureArray<SIZE>::toBytes() noexcept
{
    return static_cast<uint8_t *>(mData);
}

template <std::size_t SIZE>
const uint8_t* TESecureArray<SIZE>::toBytes() const noexcept
{
    return static_cast<const uint8_t*>(mData);
}

template <std::size_t SIZE>
std::string TESecureArray<SIZE>::toHex() const noexcept
{
    constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(SIZE * 2);
    std::size_t pos{ 0 };
    for (std::size_t pos = 0; pos < SIZE; ++pos)
    {
        auto val = uint8_t(mData[pos]);
        out.push_back(hex[val >> 4]);
        out.push_back(hex[val & 0x0f]);
    }

    return out;
}

template <std::size_t SIZE>
template <typename BINARY>
std::size_t  TESecureArray<SIZE>::copy(std::size_t offset, const BINARY& from)
{
    if ((offset >= SIZE) || (from.size() < 1))
        return 0;

    std::size_t count = from.size();
    if (count + offset > SIZE)
        count = SIZE - offset;

    NEMemory::memCopy(mData, SIZE, from.data(), count);
    return count;
}

template <std::size_t SIZE>
bool TESecureArray<SIZE>::fill(bool flag /*= true*/) noexcept
{
    mIsEmpty = flag ? false : mIsEmpty;
    return flag;
}

template <std::size_t SIZE>
void TESecureArray<SIZE>::clear() noexcept
{
    if (!mIsEmpty)
        _erase();

    mIsEmpty = true;
}

template <std::size_t SIZE>
constexpr TESecureArray<SIZE>::operator bool() const noexcept
{
    return !mIsEmpty;
}

template <std::size_t SIZE>
constexpr bool TESecureArray<SIZE>::operator ! () const noexcept
{
    return mIsEmpty;
}

template <std::size_t SIZE>
constexpr const std::byte* TESecureArray<SIZE>::data() const noexcept
{
    return mData;
}

template <std::size_t SIZE>
constexpr std::byte* TESecureArray<SIZE>::data() noexcept
{
    return mData;
}

template <std::size_t SIZE>
constexpr std::size_t TESecureArray<SIZE>::size() const noexcept
{
    return SIZE;
}

template <std::size_t SIZE>
constexpr bool TESecureArray<SIZE>::empty() const noexcept
{
    return mIsEmpty;
}

template <std::size_t SIZE>
void TESecureArray<SIZE>::_erase() noexcept
{
    NEMemory::memZero(data(), SIZE);
}
#endif  // AREG_CRYPTO
#endif  // AREG_CRYPTO_TESECUREARRAY_HPP
