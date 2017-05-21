//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <vector>
#include "uia/comm/socket_endpoint.h"

namespace uia::comm::platform {

/**
 * Find all of the local host's IP addresses (platform-specific).
 */
std::vector<endpoint> local_endpoints();

} // uia::comm::platform namespace
