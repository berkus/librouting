//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

namespace arsenal::debug
{

/**
 * Helper to output a hexadecimal value with formatting to an iostream.
 * Usage: io << hex(value, 8, true, false)
 */
struct hex_output
{
    int ch;
    int width;
    bool fill;
    bool base;

    hex_output(int c, int w, bool f, bool b) : ch(c), width(w), fill(f), base(b) {}
};

inline std::ostream& operator<<(std::ostream& o, const hex_output& hs) {
    return (o << std::setw(hs.width) << std::setfill(hs.fill ? '0' : ' ') << std::hex << (hs.base ? std::showbase : std::noshowbase) << hs.ch);
}

inline hex_output hex(int c, int w = 2, bool f = true, bool b = false) {
    return hex_output(c,w,f,b);
}

} // arsenal::debug namespace
