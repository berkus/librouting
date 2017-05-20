//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/simulation/simulator.h"
#include "uia/simulation/sim_packet.h"
#include "uia/simulation/sim_host.h"
#include "uia/simulation/sim_socket.h"
#include "uia/simulation/sim_connection.h"
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_real.hpp>
#include <boost/log/trivial.hpp>

namespace uia {
namespace simulation {

static const int packet_overhead = 32; // Bytes of link/inet overhead per packet

sim_packet::sim_packet(std::shared_ptr<sim_host> source_host,
                       uia::comm::endpoint const& src,
                       std::shared_ptr<sim_connection> pipe,
                       uia::comm::endpoint const& dst,
                       byte_array data)
    : simulator_(source_host->get_simulator())
    , from_(src)
    , to_(dst)
    , target_host_(pipe->uplink_for(source_host))
    , pipe_(pipe)
    , data_(data)
    , timer_(source_host.get())
{
    if (!target_host_) {
        logger::warning() << "Destination host " << dst << " not found on link " << pipe;
        // @todo - this packet should clean up itself somehow
    }
}

sim_packet::~sim_packet()
{
    timer_.stop();
}

void
sim_packet::send()
{
    boost::posix_time::ptime now = simulator_->current_time();

    // Get other side's params
    sim_connection::params param           = pipe_->params_for(target_host_);
    boost::posix_time::ptime& arrival_time = pipe_->arrival_time_for(target_host_);

    static boost::random::mt19937 rng;
    boost::uniform_real<> uni_dist(0, 1);

    // Simulate random loss
    if (param.loss > 0.0 and uni_dist(rng) <= param.loss) {
        logger::info() << "Packet randomly DROPPED";
        return; // @todo - this packet should clean up itself somehow
    }

    // Earliest time packet could start to arrive based on network delay
    boost::posix_time::ptime nominal_arrival = now + param.delay;

    // Compute the time the packet's first bit will actually arrive -
    // it can't start arriving sooner than the last packet finished.
    boost::posix_time::ptime actual_arrival = std::max(nominal_arrival, arrival_time);

    // If the computed arrival time is too late, drop this packet.
    // Implements a standard, basic drop-tail policy.
    if (actual_arrival > nominal_arrival + param.queue) {
        logger::info() << "Packet DROPPED";
        return; // @todo - this packet should clean up itself somehow
    }

    // Compute the amount of wire time this packet takes to transmit,
    // including some per-packet link/inet overhead
    int64_t packet_size = data_.size() + packet_overhead;
    async::timer::duration_type packet_time =
        boost::posix_time::microseconds(packet_size * 1000000 / param.rate);

    // Finally, record the time the packet will finish arriving,
    // and schedule the packet to arrive at that time.
    arrival_time  = actual_arrival + packet_time; // Updates connection's actual arrival time.
    arrival_time_ = arrival_time;

    logger::info() << "Scheduling packet to arrive at " << arrival_time_;

    target_host_->enqueue_packet(shared_from_this());

    timer_.on_timeout.connect([this](bool) { arrive(); });
    timer_.start(arrival_time - now);
}

void
sim_packet::arrive()
{
    // Make sure we're still on the destination host's queue
    if (!target_host_ or !target_host_->packet_on_queue(shared_from_this())) {
        logger::info() << "No longer queued to destination " << to_;
        return; // @todo - this packet should clean up itself somehow
    }

    timer_.stop();

    std::shared_ptr<sim_socket> socket = target_host_->socket_for_port(to_.port());
    if (!socket) {
        logger::info() << "No listener registered on port " << to_.port() << " in target host";
        return; // @todo - this packet should clean up itself somehow
    }

    // Get hold of a shared pointer to self, which is needed to keep ourselves alive a little bit
    // more.
    std::shared_ptr<sim_packet> self = shared_from_this();

    target_host_->dequeue_packet(self);

    uia::comm::socket_endpoint src_ep(socket, from_);
    socket->receive(boost::asio::const_buffer(data_.const_data(), data_.size()), src_ep);

    self.reset(); // We are ought to be deleted now.
}

} // simulation namespace
} // sss namespace
