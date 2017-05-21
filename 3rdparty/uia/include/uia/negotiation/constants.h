//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <string>

namespace magic {
using hello_packet    = std::integral_constant<uint64_t, 0x71564e7135784c68>; // "qVNq5xLh"
using cookie_packet   = std::integral_constant<uint64_t, 0x726c33416e6d786b>; // "rl3Anmxk"
using initiate_packet = std::integral_constant<uint64_t, 0x71564e7135784c69>; // "qVNq5xLi"
using message_packet  = std::integral_constant<uint64_t, 0x726c337135784c6d>; // "rl3q5xLm"
}

const std::string HELLO_NONCE_PREFIX     = "cUVVYcp-CLIENT-h";
const std::string MINUTEKEY_NONCE_PREFIX = "minute-k";
const std::string COOKIE_NONCE_PREFIX    = "cUVVYcpk";
const std::string VOUCH_NONCE_PREFIX     = "cUVVYcpv";
const std::string INITIATE_NONCE_PREFIX  = "cUVVYcp-CLIENT-i";
const std::string MESSAGE_NONCE_PREFIX   = "cUVVYcp-CLIENT-m";
