//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "arsenal/byte_array.h"
#include "uia/comm/socket_endpoint.h"
#include "uia/timer.h" // @todo move sss::async to async
#include <chrono>

namespace uia::routing {

class registration_server;

namespace internal {

// We maintain a registry_record for each registered client.
// For memory space efficiency, we keep info blocks in binary form
// and only break them out into a client_profile object when we need to.
// Private helper class for registration_server.
class registry_record
{
    friend class uia::routing::registration_server;
    static constexpr auto timeout = std::chrono::hours(1); // Records last 1 hour

    registration_server& srv;
    arsenal::byte_array const id;
    arsenal::byte_array const nhi;
    uia::comm::endpoint const ep;
    arsenal::byte_array const profile_info_;
    uia::async::timer timer_;

    registry_record(registration_server& srv,
                    arsenal::byte_array const& id,
                    arsenal::byte_array const& nhi,
                    uia::comm::endpoint const& ep,
                    arsenal::byte_array const& info); // ep based for old regserver
    // @todo Add stream-based ctor for new regserver
    ~registry_record();
};

} // internal namespace
} // uia::routing namespace
