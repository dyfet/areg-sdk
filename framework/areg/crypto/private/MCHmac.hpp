/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/MCHmac.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Digest authentication functions
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_MHMAC_HPP
#define AREG_CRYPTO_PRIVATE_MHMAC_HPP

#if AREG_CRYPTO

#include "areg/crypto/private/MCSha256.hpp"
#include "areg/crypto/private/MCSha1.hpp"

namespace MiniCrypt {
void hmac_sha256(const std::uint8_t *key, std::size_t keysize, const uint8_t *data, std::size_t size, uint8_t *out);
void hmac_sha1(const uint8_t *key, std::size_t keysize, const uint8_t *data, std::size_t size, uint8_t *out);
void pbkdf2(const uint8_t *pass, std::size_t len, const uint8_t *salt, uint32_t rounds, uint8_t *out, std::size_t size);
} // end namespace
#endif
#endif
