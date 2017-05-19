//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/simulation/sim_host.h"
#include "uia/simulation/sim_timer_engine.h"
#include "uia/simulation/simulator.h"
#include "uia/simulation/sim_socket.h"
#include "uia/simulation/sim_packet.h"
#include "uia/simulation/sim_connection.h"
#include "arsenal/algorithm.h"
#include <boost/make_unique.hpp>

using namespace std;

namespace uia {
namespace simulation {

shared_ptr<sim_host>
sim_host::create(shared_ptr<simulator> sim)
{
    auto host         = make_shared<sim_host>(sim);
    // No need to call init_link here because primary link initialized and bound there
    // is not used anywhere! Calling init_link here causes errors because of real endpoint
    // binding attempts; check how it should be set up betterer and reenable here.
    // host->init_link(nullptr);
    return host;
}

sim_host::sim_host(shared_ptr<simulator> sim)
    : host(private_tag())
    , simulator_(sim)
{
}

sim_host::~sim_host()
{
    // Close all sockets.
    for (auto socket : sockets_) {
        socket.second->unbind();
    }

    // Disconnect from other hosts.
    for (auto conn : connections_) {
        conn.second->disconnect();
    }
    assert(connections_.empty());

    packet_queue_.clear();
}

boost::posix_time::ptime
sim_host::current_time()
{
    return simulator_->current_time();
}

unique_ptr<async::timer_engine>
sim_host::create_timer_engine_for(async::timer* t)
{
    return boost::make_unique<sim_timer_engine>(t, simulator_);
}

shared_ptr<uia::comm::socket>
sim_host::create_socket()
{
    return make_shared<sim_socket>(static_pointer_cast<sim_host>(shared_from_this()));
}

void
sim_host::enqueue_packet(shared_ptr<sim_packet> packet)
{
    packet_queue_.insert(
        std::upper_bound(packet_queue_.begin(), packet_queue_.end(),
            packet, [](auto const &a, auto const &b)
            {
                return a->arrival_time() < b->arrival_time();
            }), packet);
}

void
sim_host::dequeue_packet(shared_ptr<sim_packet> packet)
{
    // @todo Replace with .erase(packet)?
    for (auto it = find(packet_queue_.begin(), packet_queue_.end(), packet);
         it != packet_queue_.end();) {
        packet_queue_.erase(it);
        it = find(packet_queue_.begin(), packet_queue_.end(), packet);
    }
}

bool
sim_host::packet_on_queue(shared_ptr<sim_packet> packet) const
{
    return find(packet_queue_.begin(), packet_queue_.end(), packet) != packet_queue_.end();
}

void
sim_host::register_connection_at(uia::comm::endpoint const& address,
                                 shared_ptr<sim_connection> conn)
{
    assert(!contains(connections_, address));
    connections_.insert(std::make_pair(address, conn));
}

void
sim_host::unregister_connection_at(uia::comm::endpoint const& address,
                                   shared_ptr<sim_connection> conn)
{
    assert(contains(connections_, address));
    assert(connections_.find(address)->second == conn);
    connections_.erase(address);
}

shared_ptr<sim_connection>
sim_host::connection_at(uia::comm::endpoint const& ep)
{
    return connections_[ep];
}

shared_ptr<sim_host>
sim_host::neighbor_at(uia::comm::endpoint const& dst, uia::comm::endpoint& src)
{
    for (auto conn : connections_) {
        shared_ptr<sim_host> uplink =
            conn.second->uplink_for(static_pointer_cast<sim_host>(shared_from_this()));
        if (conn.second->address_for(uplink) == dst) {
            src = conn.first;
            return uplink;
        }
    }
    return nullptr;
}

void
sim_host::register_socket_for_port(uint16_t port, std::shared_ptr<sim_socket> socket)
{
    assert(sockets_[port] == nullptr);
    sockets_[port] = socket;
}

void
sim_host::unregister_socket_for_port(uint16_t port, std::shared_ptr<sim_socket> socket)
{
    assert(sockets_[port] == socket);
    sockets_.erase(port);
}

shared_ptr<sim_socket>
sim_host::socket_for_port(uint16_t port)
{
    return sockets_[port];
}

vector<uia::comm::endpoint>
sim_host::local_endpoints()
{
    vector<uia::comm::endpoint> eps;
    for (auto v : connections_) {
        eps.push_back(v.first);
    }
    return eps;
}

} // simulation namespace
} // sss namespace
