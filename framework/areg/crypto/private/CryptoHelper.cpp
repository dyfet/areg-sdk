/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/CryptoHelper.cpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Helper functions conversions, used by public headers
 ************************************************************************/

#if AREG_CRYPTO

#include "areg/crypto/private/CryptoHelper.hpp"

auto NECrypto::EncodeHex(std::string_view input) noexcept -> std::string {
    constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(input.size() * 2);
    for (const auto& b : input) {
        auto val = uint8_t(b);
        out.push_back(hex[val >> 4]);
        out.push_back(hex[val & 0x0f]);
    }
    return out;
}

#endif

// WARNING: THIS IS TEMPORARY CODE TO HELP TESTING BUILD OF HEADER ONLY
// COMPONENTS THAT HAVE NO BUILDS YET.  REMOVE WHEN NO LONGER NEEDED>

#include "areg/crypto/TESecureArray.hpp"

