#pragma once

#include "arsenal/fusionary.hpp"

namespace uia::fusionary_types {

struct uint24_t
{
    uint16_t high;
    uint8_t low;
    operator uint64_t() { return uint64_t(high) << 8 | low; }
};

struct uint40_t
{
    uint32_t high;
    uint8_t low;
    operator uint64_t() { return uint64_t(high) << 8 | low; }
};

struct uint48_t
{
    uint32_t high;
    uint16_t low;
    operator uint64_t() { return uint64_t(high) << 16 | low; }
};

struct uint56_t
{
    uint32_t high;
    uint24_t low;
    operator uint64_t() { return uint64_t(high) << 24 | low; }
};

} // uia::fusionary_types namespace

// clang-format off
BOOST_FUSION_ADAPT_STRUCT(
    uia::fusionary_types::uint24_t,
    (uint16_t, high)
    (uint8_t, low)
);

BOOST_FUSION_ADAPT_STRUCT(
    uia::fusionary_types::uint40_t,
    (uint32_t, high)
    (uint8_t, low)
);

BOOST_FUSION_ADAPT_STRUCT(
    uia::fusionary_types::uint48_t,
    (uint32_t, high)
    (uint16_t, low)
);

BOOST_FUSION_ADAPT_STRUCT(
    uia::fusionary_types::uint56_t,
    (uint32_t, high)
    (uia::fusionary_types::uint24_t, low)
);

BOOST_FUSION_DEFINE_STRUCT(
    (uia)(fusionary_types), packet_sequence_number,
    (uint16_t, size2)
    (uint32_t, size4)
    (uia::fusionary_types::uint48_t, size6)
    (uint64_t, size8)
);
// clang-format on

// Some basic conversions
//
template <size_t N>
std::array<uint8_t, N>
as_array(std::string const& s)
{
    assert(s.size() == N);
    std::array<uint8_t, N> ret;
    std::copy(s.begin(), s.end(), ret.begin());
    return ret;
}

template <size_t N>
std::string
as_string(std::array<uint8_t, N> const& a)
{
    std::string ret;
    ret.resize(N);
    std::copy(a.begin(), a.end(), ret.begin());
    return ret;
}

inline std::string
as_string(arsenal::fusionary::rest_t const& a)
{
    return a.data;
}

