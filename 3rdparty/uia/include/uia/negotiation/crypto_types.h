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
using nonce64    = sodiumpp::nonce<crypto_box_NONCEBYTES - 8, 8>;
using nonce128   = sodiumpp::nonce<crypto_box_NONCEBYTES - 16, 16>;
using recv_nonce = sodiumpp::source_nonce<crypto_box_NONCEBYTES>;

// @todo Move this to krypto?
