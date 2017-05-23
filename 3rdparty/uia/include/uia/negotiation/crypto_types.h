//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "sodiumpp/sodiumpp.h"

using eckey_t    = std::array<uint8_t, 32>;
using cnonce8_t  = std::array<uint8_t, 8>;
using cnonce16_t = std::array<uint8_t, 16>;
using box48_t    = std::array<uint8_t, 48>;
using box64_t    = std::array<uint8_t, 64>;
using box80_t    = std::array<uint8_t, 80>;
using box96_t    = std::array<uint8_t, 96>;
using box144_t   = std::array<uint8_t, 144>;
using nonce128   = sodiumpp::nonce<16>;

// @todo Move this to krypto?
