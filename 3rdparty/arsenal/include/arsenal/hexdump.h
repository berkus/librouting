//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "arsenal/byte_array.h"

namespace arsenal::debug
{

/// octet_stride specifies number of bytes to print in one column
/// octet_split causes run of bytes to be separated by extra space in given column
/// setting it to 0 disables separation
void hexdump(byte_array data,
             size_t octet_stride = 16,
             size_t octet_split = 8,
             size_t indent_spaces = 0);

} // arsenal::debug namespace
