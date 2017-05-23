//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "arsenal/fusionary.hpp"
#include "uia/basic_framing_types.h"
#include "uia/negotiation/crypto_types.h"
#include "uia/negotiation/constants.h"

//=================================================================================================
// Channel layer - transmitted packets
//=================================================================================================

// clang-format off
BOOST_FUSION_DEFINE_STRUCT(
    (uia)(packets), responder_cookie,
    (cnonce16_t, nonce)
    (box80_t, box)
);

BOOST_FUSION_DEFINE_STRUCT(
    (uia)(packets), hello_packet_header,
    (uia::magic::hello_packet, magic)
    (eckey_t, initiator_shortterm_public_key)
    (box64_t, zeros)
    (cnonce8_t, nonce)
    (box80_t, box)
);

BOOST_FUSION_DEFINE_STRUCT(
    (uia)(packets), cookie_packet_header,
    (uia::magic::cookie_packet, magic)
    (cnonce16_t, nonce)
    (box144_t, box)
);

BOOST_FUSION_DEFINE_STRUCT(
    (uia)(packets), initiate_packet_header,
    (uia::magic::initiate_packet, magic)
    (eckey_t, initiator_shortterm_public_key)
    (uia::packets::responder_cookie, responder_cookie)
    (cnonce8_t, nonce)
    (arsenal::fusionary::rest_t, box) // variable size box -- see struct below
);

BOOST_FUSION_DEFINE_STRUCT(
    (uia)(packets), initiate_packet_box,
    (eckey_t, initiator_longterm_public_key)
    (cnonce16_t, vouch_nonce)
    (box48_t, vouch)
    (arsenal::fusionary::rest_t, box) // variable size data containing initial frames
);

BOOST_FUSION_DEFINE_STRUCT(
    (uia)(packets), message_packet_header,
    (uia::magic::message_packet, magic)
    (eckey_t, shortterm_public_key)
    (cnonce8_t, nonce)
    (arsenal::fusionary::rest_t, box) // variable size box containing message
);
// clang-format on

inline std::string
as_string(uia::packets::responder_cookie const& a)
{
    return as_string(a.nonce) + as_string(a.box);
}
