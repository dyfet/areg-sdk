/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/crypto/private/MCHelper.hpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Helper functions for Minicrypt back-end
 ************************************************************************/

#ifndef AREG_CRYPTO_PRIVATE_MCHELPER_HPP
#define AREG_CRYPTO_PRIVATE_MCHELPER_HPP

#if AREG_CRYPTO

#include <cstdint>
#include <cstring>
#include <cstddef>

namespace MiniCrypt {
void *memset(void *ptr, int value, std::size_t size);
void memcpy(void *outp, const void *inp, std::size_t len);
std::size_t strlen(const char *cp, std::size_t max);
uint64_t keyvalue(uint8_t *digest, std::size_t size);
}

#endif  // AREG_CRYPTO
#endif  // AREG_CRYPTO_PRIVATE_MCHELPER_HPP

