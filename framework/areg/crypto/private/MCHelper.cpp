/************************************************************************
 * This file is part of the AREG SDK core engine.
 * AREG SDK is dual-licensed under Free open source (Apache version 2.0
 * License) and Commercial (with various pricing models) licenses, depending
 * on the nature of the project (commercial, research, academic or free).
 * You should have received a copy of the AREG SDK license description in LICENSE.txt.
 * If not, please contact to info[at]aregtech.com
 *
 * \file        areg/logging/private/Layouts.cpp
 * \ingroup     AREG SDK, Automated Real-time Event Grid Software Development Kit
 * \author      David Sugar
 * \brief       Helper functions for Minicrypt back-end
 ************************************************************************/

#if AREG_CRYPTO

#include "MCHelper.hpp"

//////////////////////////////////////////////////////////////////////////
// A non-cachable memory clean function
//////////////////////////////////////////////////////////////////////////
void *MiniCrypt::memset(void *ptr, int value, std::size_t size) {
    volatile uint8_t *volatile p = (volatile uint8_t *volatile)ptr;
    if (!p) return nullptr;
    while (size--) {
        *p++ = (uint8_t)value;
    }
    return ptr;
}

void MiniCrypt::safememcpy(void *outp, const void *inp, std::size_t len) {
    if (!outp || !inp || outp == inp || len == 0) return;
    uint8_t *out = (uint8_t *)outp;
    const uint8_t *in = (uint8_t *)inp;
    if ((out > in && out < in + len) || (in > out && in < out + len)) return;
    std::size_t i;
    for (i = 0; i < len; i++)
        out[i] = in[i];
}

//////////////////////////////////////////////////////////////////////////
// A deterministic strlen for raw C strings
//////////////////////////////////////////////////////////////////////////
std::size_t MiniCrypt::strlen(const char *cp, std::size_t max) {
    std::size_t count = 0;
    if (!cp) return 0;
    while (*cp && (++count < max))
        ++cp;
    if (*cp) return 0; // invalid or overflow
    return count;
}

uint64_t MiniCrypt::keyvalue(uint8_t *digest, std::size_t size) {
    uint64_t result = 0;
    for (unsigned i = 0; i < sizeof(result); ++i) {
        result = (result << 8) | digest[i];
    }
    MiniCrypt::memset(digest, 0, size);
    return result;
}
#endif

