//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2013, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <memory>
#include <vector>
#include <boost/signals2/signal.hpp>
#include "byte_array.h"

namespace ssu {
class host;
} // ssu namespace

namespace uia {
namespace routing {

class client;

/**
 * Routing client coordinator manages set of routing clients providing information about
 * peer locations and keyword searches.
 */
class client_coordinator
{
    std::shared_ptr<ssu::host> host_;

    class coordinator_impl;
    std::shared_ptr<coordinator_impl> pimpl_;
public:
    client_coordinator(std::shared_ptr<ssu::host> host); // Can't have shared_ptr to host here, as it creates a loop.
    std::vector<client*> routing_clients() const;

    void add_routing_client(client* c);
    void remove_routing_client(client* c);
    void insert_nonce(byte_array const& nonce, client* c);
    void clear_nonce(byte_array const& nonce);

    typedef boost::signals2::signal<void (client*)> routing_client_signal;
    routing_client_signal on_routing_client_created;
    routing_client_signal on_routing_client_deleted;
};

} // routing namespace
} // uia namespace
