//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <memory>
#include <boost/signals2/signal.hpp>
#include "sodiumpp/sodiumpp.h"
#include "uia/peer_identity.h"
#include "uia/comm/socket_endpoint.h"
#include "uia/channels/socket_channel.h"
#include "uia/timer.h"
#include "uia/forward_ptrs.h"

namespace uia::negotiation {

/**
 * Key exchange initiator maintains host state with respect to initiated key exchanges.
 * One initiator keeps state about key exchange with one peer.
 *
 * XXX make key_initiator an abstract base class like key_responder,
 * calling a create_channel() method when it needs to set up a channel
 * rather than requiring the channel to be passed in at the outset.
 *
 * The implemented class of this abstract base is @c channel_initiator.
 */

// @todo Single initiator may set up channel to single peer_identity on multiple endpoints?

// kex_responder side:
// Hello and Cookie processing requires no state.
// Only when Initiate is received and passes validation we create channel
// and start it.
//
// kex_initiator side:
// 1) attempt to send Hello packets periodically until we get a Cookie or give up
// 2) when Cookie is received, allocate our state and attempt to send Initiate with
// some data.
// 3) If after retrying Initiate we don't get response for 30 seconds, send another Hello.
//
class initiator : public std::enable_shared_from_this<initiator>
{
    // This is what it's all happening for. Channel we'll create and hopefully return upon
    // established connection via on_completed() signal.
    socket_channel_ptr channel_;

    host_ptr host_;
    uia::comm::socket_endpoint target_; ///< Remote endpoint we're trying to contact.
    uia::peer_identity remote_id_;      ///< Target's host id.
    bool early_{true};                  ///< This initiator can still be canceled.

    /**
     * Current phase of the protocol negotiation.
     */
    enum class state
    {
        idle,
        hello,    // gives server client's short-term public key
        initiate, // auth phase
        done
    } state_{state::idle};

    uia::async::timer retransmit_timer_;

    void retransmit(bool fail);
    void cookie_expired();
    void create_channel(sodiumpp::box_secret_key local_short,
                        sodiumpp::box_public_key remote_short,
                        sodiumpp::box_public_key remote_long,
                        uia::comm::socket_endpoint const& responder_ep);
    void done();

    // Key exchange state

    // We know server long term public key on start - this is remote_id_
    // We need to remember short-term server public key
    sodiumpp::box_secret_key short_term_secret_key; // out short-term key (generated)
    std::string server_short_term_public_key;   // remote_peer.short_term key

    std::string minute_cookie_; // one-minute cookie received after hello packet response
    uia::async::timer minute_timer_;

public:
    /// Start key negotiation with remote peer. If successful, this negotiation will yield a
    /// new channel via `create_channel()` call.
    initiator(host_ptr host, peer_identity const& target_peer, comm::socket_endpoint target);
    ~initiator();

    /**
     * Actually start hello phase.
     */
    void exchange_keys();

    /**
     * Cancel all of this kex_initiator's activities
     * (without actually deleting the object just yet).
     */
    void cancel();

    inline uia::comm::socket_endpoint remote_endpoint() const { return target_; }
    inline bool is_done() const { return state_ == state::done; }

    /**
     * Key exchange protocol from the initiator standpoint.
     */
    void send_hello();
    void got_cookie(boost::asio::const_buffer buf, uia::comm::socket_endpoint const& src);
    void send_initiate(std::string cookie, std::string payload);

    /**
     * Send completion signal, giving created channel on success or nullptr on failure.
     */
    using completion_signal = boost::signals2::signal<void(initiator_ptr, socket_channel_ptr)>;
    completion_signal on_completed;
};

} // uia::negotiation namespace
