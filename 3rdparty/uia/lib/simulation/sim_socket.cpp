//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/simulation/sim_socket.h"
#include "uia/simulation/sim_connection.h"
#include "uia/simulation/sim_host.h"
#include "uia/simulation/sim_packet.h"

using namespace std;

namespace uia {
namespace simulation {

sim_socket::sim_socket(sim_host_ptr host)
    : uia::comm::socket(host)
    , simulator_(host->get_simulator())
    , host_(host)
{
}

sim_socket::~sim_socket()
{
    unbind();
}

bool
sim_socket::bind(uia::comm::endpoint ep)
{
    assert(port_ == 0);

    if (ep.port() == 0) {
        int port = 1024;
        while (port < 65536 and host_->socket_for_port(port) != nullptr)
            ++port;

        if (port >= 65536)
            return false;

        port_ = port;
    } else {
        port_ = ep.port();
    }

    host_->register_socket_for_port(port_,
                                    static_pointer_cast<sim_socket>(shared_from_this()));

    logger::debug() << "Bound virtual socket on " << ep;

    set_active(true);
    return true;
}

void
sim_socket::unbind()
{
    if (port_ > 0) {
        host_->unregister_socket_for_port(port_,
                                          static_pointer_cast<sim_socket>(shared_from_this()));
        port_ = 0;
    }
    set_active(false);
}

// Target address must be routable to in order to send.
// Find the destination host in the "routing table" (a simple list of neighbors).
bool
sim_socket::send(uia::comm::endpoint ep, const char* data, size_t size)
{
    assert(port_ > 0);

    uia::comm::endpoint src;
    src.port(port_);
    sim_host_ptr dest_host = host_->neighbor_at(ep, src);
    if (!dest_host) {
        logger::warning() << "Unknown or non-adjacent target host " << ep;
        return false;
    }

    sim_connection_ptr pipe(host_->connection_at(src));
    assert(pipe);

    make_shared<sim_packet>(host_, src, pipe, ep, byte_array(data, size))->send();

    return true;
}

vector<uia::comm::endpoint>
sim_socket::local_endpoints()
{
    vector<uia::comm::endpoint> result;
    for (auto ep : host_->local_endpoints()) {
        result.emplace_back(ep.address(), local_port());
    }
    return result;
}

} // simulation namespace
} // sss namespace
