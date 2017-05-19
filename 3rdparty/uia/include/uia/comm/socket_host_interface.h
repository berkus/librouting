//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "uia/forward_ptrs.h"

namespace uia {
namespace comm {

/**
 * Interface used by socket layer to work with the host state.
 * Must be implemented by real host implementation.
 */
class socket_host_interface
{
public:
    // Interface used by socket to register itself on the host.
    virtual void activate_socket(socket_wptr) = 0;
    virtual void deactivate_socket(socket_wptr) = 0;
};

} // comm namespace
} // uia namespace
