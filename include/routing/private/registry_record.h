//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "arsenal/byte_array.h"
#include "ssu/host.h"//@todo Remove this when comm/socket is decoupled from ssu
#include "comm/socket.h"
#include "ssu/timer.h" // @todo move ssu::async to async

namespace uia {
namespace routing {

class registration_server;

namespace internal {

// We maintain a registry_record for each registered client.
// For memory space efficiency, we keep info blocks in binary form
// and only break them out into a client_profile object when we need to.
// Private helper class for registration_server.
class registry_record
{
    friend class uia::routing::registration_server;
    static constexpr uint32_t timeout_seconds = (1*60*60);   // Records last 1 hour

    registration_server& srv;
    byte_array const id;
    byte_array const nhi;
    uia::comm::endpoint const ep;
    byte_array const profile_info_;
    ssu::async::timer timer_;

    registry_record(registration_server& srv, byte_array const& id, byte_array const& nhi,
        uia::comm::endpoint const& ep, byte_array const& info); // ep based for old regserver
    // @todo Add stream-based ctor for new regserver
    ~registry_record();
};

} // internal namespace
} // routing namespace
} // uia namespace
