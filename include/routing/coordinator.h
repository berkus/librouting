//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <memory>
#include <vector>
#include <boost/signals2/signal.hpp>
#include "arsenal/byte_array.h"

namespace uia {
class host;
} // uia namespace

namespace uia::routing {

class client;

/**
 * Routing client coordinator manages set of routing clients providing information about
 * peer locations and keyword searches.
 */
class client_coordinator
{
    uia::host& host_;

    class coordinator_impl;
    std::shared_ptr<coordinator_impl> pimpl_;
public:
    client_coordinator(std::shared_ptr<uia::host> host);
    std::vector<client*> routing_clients() const;

    void add_routing_client(client* c);
    void remove_routing_client(client* c);
    void insert_nonce(arsenal::byte_array const& nonce, client* c);
    void clear_nonce(arsenal::byte_array const& nonce);

    using routing_client_signal = boost::signals2::signal<void (client*)>;
    routing_client_signal on_routing_client_created;
    routing_client_signal on_routing_client_deleted;
};

} // uia::routing namespace
