//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

namespace uia {
namespace comm {

constexpr size_t   MIN_PACKET_SIZE = 64;
constexpr uint16_t DEFAULT_PORT    = 9660;
constexpr size_t   MTU             = 1280; // an ipv6 frame size, not fragmentable

} // comm namespace
} // uia namespace
