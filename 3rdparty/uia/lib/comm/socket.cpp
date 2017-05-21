//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/comm/socket.h"
#include "arsenal/algorithm.h"
#include "arsenal/subrange.h"
#include "uia/comm/packet_receiver.h" // FIXME
#include "uia/comm/socket_protocol.h"
#include "uia/host.h"
#include <boost/log/trivial.hpp>

using namespace std;
using namespace boost;

namespace uia::comm {

//=================================================================================================
// socket
//=================================================================================================

socket::~socket()
{
}

string
socket::status_string(socket::status s)
{
    switch (s) {
        case status::down: return "down";
        case status::stalled: return "stalled";
        case status::up: return "up";
    }
}

void
socket::set_active(bool active)
{
    active_ = active;
    if (active_) {
        host_->activate_socket(shared_from_this());
    } else {
        host_->deactivate_socket(shared_from_this());
    }
}

/**
 * Now the curvecp packets are impassable blobs of encrypted data.
 * The only magic we can use to differentiate is 8 byte header,
 * saying if this is Hello, Cookie, Initiate or Message packet.
 * Hello, Cookie and Initiate packets go to key exchange handler.
 * Message packets go to message handler which forwards them to
 * appropriate channel based on source public key field.
 */
void
socket::receive(asio::const_buffer msg, socket_endpoint const& src)
{
    if (buffer_size(msg) >= uia::comm::MIN_PACKET_SIZE) {
        // logger::file_dump(msg, "received raw socket packet");

        const uint64_t magic = *asio::buffer_cast<const uint64_t*>(msg);

        if (auto rcvr = host_->receiver_for(magic).lock()) {
            return rcvr->receive(msg, src);
        }
    }
    // Ignore too small or unrecognized packets.
}

bool
socket::is_congestion_controlled(endpoint const&)
{
    return false;
}

size_t
socket::may_transmit(endpoint const&)
{
    BOOST_LOG_TRIVIAL(fatal) << "may_transmit() called on a non-congestion-controlled socket";
    return 0;
}

} // uia::comm namespace
