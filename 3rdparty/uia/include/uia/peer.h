//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <mutex>
#include "uia/peer_identity.h"
#include "uia/forward_ptrs.h"
#include "uia/comm/endpoint_set.h"
#include "uia/comm/socket.h"

namespace uia {

using channel_key = std::array<uint8_t, 32>;

namespace internal {

/**
 * Private helper class to keep information about a peer we are establishing connection with.
 * Contains cryptographic identifier as well as a set of possible endpoint addresses.
 * Keeps track of established channels.
 *
 * - peer id
 * - known IP endpoints used by this peer / (@todo their NAT state)
 * - currently open channels
 * - open channels status (ok, stalled, disconnected)
 * - outgoing kex sessions in progress
 */
class peer
{
    host_ptr host_;                                      ///< Per-host state.
    const uia::peer_identity remote_id_;                 ///< Host ID of target.
    comm::endpoint_set locations_;                       ///< Potential peer locations known
    std::map<channel_key, socket_channel_ptr> channels_; ///< Currently established channels.
    // channel_key is short-term peer's public key

    std::map<comm::socket_endpoint, negotiation::initiator_ptr> key_exchanges_initiated_;
    std::mutex kex_mutex_;

    inline uia::peer_identity remote_host_id() const { return remote_id_; }

    /**
     * Initiate a key exchange attempt to a given endpoint,
     * if such an attempt isn't already in progress.
     */
    void initiate_key_exchange(comm::socket_wptr s, comm::endpoint const& ep);
    // ^^ @todo Do we care about EPs now at all? new key exchange would initiate a new channel
    // each time this is called.

    // Handlers.
    void completed(negotiation::initiator_ptr ki, socket_channel_ptr chan); // KEX inited
    void channel_status_changed(comm::socket::status new_status);

public:
    peer(host_ptr host, uia::peer_identity remote_id);
    ~peer();

    /**
     * Initiate a connection attempt to target host by any means possible,
     * hopefully at some point resulting in an active channel.
     * Eventually emits a on_channel_connected or on_channel_failed signal.
     */
    void connect_channel();

    /**
     * Called by stream_channel::start() whenever a new channel
     * (either incoming or outgoing) successfully starts.
     */
    void channel_started(socket_channel* channel);

    /**
     * Supply an endpoint hint that may be useful for finding this peer.
     */
    void add_location_hint(comm::endpoint const& hint);

    using channel_state_signal = boost::signals2::signal<void(void)>;
    using socket_status_changed_signal =
        boost::signals2::signal<void(comm::socket_wptr, comm::socket::status)>;

    /**
     * Primary channel connection attempt succeeded.
     */
    channel_state_signal on_channel_connected;
    /**
     * Connection attempt failed. @fixme should work differently with multiple channels.
     */
    channel_state_signal on_channel_failed;
    /**
     * Indicates when this stream peer observes a change in socket status.
     */
    socket_status_changed_signal on_socket_status_changed;
};

} // internal namespace
} // uia namespace
