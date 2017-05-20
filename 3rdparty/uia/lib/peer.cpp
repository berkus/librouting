//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/peer.h"
#include "uia/host.h"
#include "uia/channels/socket_channel.h"
#include "uia/negotiation/initiator.h"
#include <boost/log/trivial.hpp>

using arsenal::contains;

namespace uia {

//=================================================================================================
// endpoint_set
//=================================================================================================

namespace {

// Return number of high-order bits that are the same between two addresses.
template <size_t N>
int bit_affinity(std::array<unsigned char, N> a, std::array<unsigned char, N> b)
{
    for (size_t i = 0; i < N; ++i) {
        auto x = a[i] ^ b[i];
        if (x == 0) {
            continue;
        }
        // Byte difference detected - find first bit difference
        for (auto j = 0; j < 8; ++j) {
            if (x & (0x80 >> j)) {
                return i * 8 + j;
            }
        }
        // Should never be reached
        assert(0);
    }
    return N * 8; // addresses are identical
}

// Calculate affinity in bits of two IP addresses.
static int
affinity(boost::asio::ip::address a, boost::asio::ip::address b)
{
    if (a.is_v6() != b.is_v6()) {
        // BOOST_LOG_TRIVIAL(debug) << "Addresses " << a << " and " << b << " are not comparable";
        return 0; // ipv4 and ipv6 do not match at all
    }
    if (a.is_v6()) {
        auto aff = bit_affinity(a.to_v6().to_bytes(), b.to_v6().to_bytes());
        // BOOST_LOG_TRIVIAL(debug) << "Addresses " << a << " and " << b << " have affinity " << aff;
        return aff;
    } else {
        auto aff = bit_affinity(a.to_v4().to_bytes(), b.to_v4().to_bytes());
        // BOOST_LOG_TRIVIAL(debug) << "Addresses " << a << " and " << b << " have affinity " << aff;
        return aff;
    }
}

} // anonymous namespace

namespace comm {

std::list<endpoint>
endpoint_set::affinity_sorted_to(const endpoint other)
{
    std::list<endpoint> out;
    std::copy(begin(), end(), std::back_inserter(out));
    out.sort([other](auto const& a, auto const& b) {
        return affinity(a.address(), other.address()) > affinity(b.address(), other.address());
    });
    return out;
}

} // comm namespace

//=================================================================================================
// peer
//=================================================================================================
namespace internal {

peer::peer(host_ptr host, uia::peer_identity remote_id)
    : host_(host)
    , remote_id_(remote_id)
    // , reconnect_timer_(host.get())
{
    assert(!remote_id.is_null());
    // reconnect_timer_.on_timeout.connect([this](bool failed) { retry_timeout(); });
    host_->instantiate_responder();// should happen at some point before we start kex
}

peer::~peer()
{}

// void
// peer::retry_timeout()
// {
//     // If we actually have an active channel now, do nothing.
//     // if (primary_channel_ and primary_channel_->link_status() == socket::status::up)
//     // @todo:
//     // if (channels_.count() > 0 and channels_.any(|c| c.link_status() == status::up))
//     // return;

//     // Notify any waiting streams of failure
//     if (no_lookups_possible()) {
//         on_channel_failed();
//     }

//     // If there are (still) any waiting streams, fire off a new batch of connection attempts.
//     connect_channel();
// }

void
peer::connect_channel()
{
    // assert(!remote_id_.is_null());

    // if (primary_channel_ and primary_channel_->link_status() == socket::status::up)
        // return; // Already have a working channel; don't need another yet.

    // @todo Need a way to determine if streams need to send. If no streams waiting to send
    // on this channel, don't even bother.
    //
    // if (receivers(SIGNAL(flowConnected())) == 0) return;

    BOOST_LOG_TRIVIAL(debug) << "Trying to connect channel with peer " << remote_id_;

    // @todo Ask routing to figure out other possible endpoints for this peer.

    // Send a lookup request to each known registration server.
    // for (auto rc : host_->coordinator->routing_clients()) {
    //     if (!rc->is_ready()) {
    //         // Can't poll an inactive regserver
    //         rc->on_ready.connect([this, rc] { routing_client_ready(rc); });
    //         continue;
    //     }

    //     routing_client_ready(rc);
    // }

    // Initiate key exchange attempts to all already-known endpoints
    // using each of the network links we have available.
    for (auto endpoint : locations_) {
        for (auto sock : host_->active_sockets()) {
            initiate_key_exchange(sock, endpoint);
        }
    }

    // Keep firing off connection attempts periodically
    // reconnect_timer_.start(connect_retry_period);
}

void
peer::initiate_key_exchange(uia::comm::socket_wptr l, uia::comm::endpoint const& ep)
{
    assert(ep != comm::endpoint());

    // No need to initiate new channels if we already have a working one.
    // if (primary_channel_ and primary_channel_->link_status() == socket::status::up)
    // @todo:
    // if (channels_.count() > 0 and channels_.any(|c| c.link_status() == status::up))
    // return;

    // Don't simultaneously initiate multiple channels to the same endpoint.
    // @todo Eventually multipath support is needed.
    uia::comm::socket_endpoint lep(l, ep);
    {
        std::lock_guard<std::mutex> lock(kex_mutex_);
        if (contains(key_exchanges_initiated_, lep)) {
            BOOST_LOG_TRIVIAL(debug) << "Already attempting connection to " << ep;
            return;
        }
    }

    BOOST_LOG_TRIVIAL(debug) << "Initiating key exchange from socket " << l.lock() << " to remote endpoint "
                    << ep;

    // Make sure our responder exists to receive and dispatch incoming
    // key exchange control packets.
    host_->instantiate_responder();

    // @todo: Key exchange should spawn channel once we finalize key exchange.

    // Create and bind a new channel.
    // channel* chan = new stream_channel(host_, this, remote_id_);
    // if (!chan->bind(l, ep)) {
    //     BOOST_LOG_TRIVIAL(warning) << "Could not bind new channel to target " << ep;
    //     delete chan;
    //     return on_channel_failed();
    // } // @sa stream_responder::create_channel

    // Start the key exchange process for the channel.
    auto init = std::make_shared<negotiation::initiator>(host_, remote_id_, lep);

    init->on_completed.connect([this](negotiation::initiator_ptr ki, socket_channel_ptr ch) { completed(ki, ch); });

    {
        std::lock_guard<std::mutex> lock(kex_mutex_);
        key_exchanges_initiated_.insert(make_pair(lep, init));
    }

    init->exchange_keys();
}

void
peer::channel_started(socket_channel* channel)
{
    BOOST_LOG_TRIVIAL(debug) << "Stream peer - channel " << channel << " started";

    assert(channel->is_active());
    // assert(channel->target_peer() == this);
    // assert(channel->link_status() == socket::status::up);

    // @todo Sort established channels by some attributes (e.g. purpose, negotiated settings etc)

    // @todo Change this logic completely, as currently we can have many parallel channels
    // between two peers at once. Each may have its own decongestion and encryption settings.
    // Keep a list of channels instead of single primary channel in stream_peer.
    // if (primary_channel_) {
    // If we already have a working primary channel, we don't need a new one.
    // if (primary_channel_->link_status() == socket::status::up)
    // return; // Shutdown the channel?

    // But if the current primary is on the blink, replace it.
    // clear_primary_channel();
    // }

    BOOST_LOG_TRIVIAL(debug) << "Stream peer - new primary channel " << channel;

    // Use this channel as our primary channel for this target.
    // primary_channel_ = channel;
    // stall_warnings_ = 0;

    // Watch the link status of our primary channel, so we can try to replace it if it fails.
    // primary_channel_link_status_connection_ = primary_channel_->on_link_status_changed.connect(
    // [this](socket::status new_status) { primary_status_changed(new_status); });

    // Notify all waiting streams
    on_channel_connected();
    // on_socket_status_changed(comm::socket::status::up);
}
/*
void
stream_peer::clear_primary_channel()
{
    if (!primary_channel_)
        return;

    auto old_primary = primary_channel_;
    primary_channel_ = nullptr;

    // Avoid getting further primary link status notifications from it
    primary_channel_link_status_connection_.disconnect();

    // Clear all transmit-attachments
    // and return outstanding packets to the streams they came from.
    old_primary->detach_all();
}*/

void
peer::add_location_hint(uia::comm::endpoint const& hint)
{
    // assert(!remote_id_.is_empty());
    // assert(!hint.empty());

// std::lock_guard<std::mutex> lock(loc_mutex_);
    if (contains(locations_, hint)) {
        return; // We already know; sit down...
    }

    BOOST_LOG_TRIVIAL(debug) << "Found endpoint " << hint << " for target " << remote_id_;

    // Add this endpoint to our set
    locations_.insert(hint);

    // Attempt a connection to this endpoint
    // @todo ONLY if there's outstanding comm packets for this peer and no active channels
    // available...
    //
    // for (auto s : host_->active_sockets()) {
    //     initiate_key_exchange(s, hint);
    // }
}

void
peer::completed(negotiation::initiator_ptr ki, socket_channel_ptr chan)
{
    assert(ki and ki->is_done());

    // Remove and schedule the key initiator for deletion, in case it wasn't removed already
    // (e.g., if key agreement failed).
    //
    // @todo Delete channel automatically if key_initiator failed...
    uia::comm::socket_endpoint lep = ki->remote_endpoint();

    // BOOST_LOG_TRIVIAL(debug) << "Stream peer key exchange for ID " << remote_id_ << " to " << lep
    //                 << (success ? " succeeded" : " failed");
    {
        std::lock_guard<std::mutex> lock(kex_mutex_);
        assert(!contains(key_exchanges_initiated_, lep) or key_exchanges_initiated_[lep] == ki);
        key_exchanges_initiated_.erase(lep);
    }

    ki->cancel();
    ki.reset();

    // If unsuccessful, notify waiting streams.
    // if (!success) {
        // if (no_lookups_possible()) {
        //     return on_channel_failed();
        // }
        // return; // There's still hope
    // }

    // We should have an active primary channel at this point,
    // since stream_channel::start() attaches the channel if there isn't one.
    // Note: the reason we don't just set the primary right here
    // is because stream_channel::start() gets called on incoming streams too,
    // so servers don't have to initiate back-channels to their clients.

    // @todo This invariant doesn't hold here, fixme.
    // assert(primary_channel_ and primary_channel_->link_status() ==
    // uia::comm::socket::status::up);
}

void
peer::channel_status_changed(comm::socket::status new_status)
{
    // assert(primary_channel_);

    if (new_status == comm::socket::status::up) {
        // stall_warnings_ = 0;
        // Now that we (again?) have a working primary channel, cancel and delete all
        // outstanding kex_initiators that are still in an early enough stage not
        // to have possibly created receiver state.
        // (If we were to kill a non-early key_initiator, the receiver might pick one
        // of those streams as _its_ primary and be left with a dangling channel!)
        // For Multipath-SSS to work we rather should not destroy them here and set up
        // multiple channels at once.
        // @todo Even trickier, kill only initiators to already established endpoints!
        std::lock_guard<std::mutex> lock(kex_mutex_);
        auto ki_copy = key_exchanges_initiated_;
        for (auto ki : ki_copy) {
            auto initiator = ki.second;
            // if (!initiator->is_early()) {
            // continue; // too late - let it finish
            // }
            BOOST_LOG_TRIVIAL(debug) << "Deleting " << initiator << " for " << remote_id_ << " to "
                            << initiator->remote_endpoint();

            assert(ki.first == initiator->remote_endpoint());
            key_exchanges_initiated_.erase(ki.first);
            initiator->cancel();
            initiator.reset();
        }

        return ;//on_socket_status_changed(new_status);
    }

    if (new_status == comm::socket::status::stalled) {
        // if (++stall_warnings_ < stall_warnings_max) {
        //     BOOST_LOG_TRIVIAL(warning) << "Primary channel stall " << stall_warnings_ << " of "
        //                       << stall_warnings_max;
        //     return on_link_status_changed(new_status);
        // }
    }

    // Primary is at least stalled, perhaps permanently failed -
    // start looking for alternate paths right away for quick response.
    // connect_channel();

    // Pass the signal on to all streams connected to this peer.
    // on_socket_status_changed(new_status);
}

} // internal namespace
} // uia namespace
