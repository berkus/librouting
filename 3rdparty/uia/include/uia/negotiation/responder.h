//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <set>
#include <boost/signals2/signal.hpp>
#include "sodiumpp/sodiumpp.h"
#include "uia/peer_identity.h"
#include "uia/comm/socket_endpoint.h"
#include "uia/comm/packet_receiver.h"
#include "uia/timer.h"
#include "uia/forward_ptrs.h"

namespace uia::negotiation {

/**
 * This abstract base class manages the responder side of the key exchange.
 * It uses packet_receiver interface as base to receive negotiation protocol
 * control packets and respond to incoming key exchange requests.
 *
 * It forwards received requests to a corresponding key initiator in the host state
 * (via host_->get_initiator()).
 *
 * The implemented subclass of this abstract base is @c stream_responder.
 */
class responder : public comm::packet_receiver
{
    // This is what it's all happening for. Channel we'll create and hopefully return upon
    // established connection via on_completed() signal.
    socket_channel_ptr channel_;

    host_ptr host_;

    sodiumpp::secret_key short_term_key; // generated
    sodiumpp::secret_key minute_key;
    std::set<std::string> cookie_cache;
    std::string client_short_term_key;

    uia::async::timer minute_key_rotation_;

public:
    /**
     * Create a key exchange responder and set it to listen on a particular socket.
     */
    responder(host_ptr host);

    // virtual host_ptr get_host() { return host_; }

    /**
     * Socket calls this with key exchange messages intended for us.
     * @param msg Data packet.
     * @param src Origin endpoint.
     */
    void receive(boost::asio::const_buffer msg, comm::socket_endpoint src) override;

    /**
     * Send a probe chunk to some network address,
     * presumably a client we've discovered somehow is trying to reach us,
     * in order to punch a hole in any NATs we may be behind
     * and prod the client into (re-)sending us its "hello" immediately.
     */
    void send_probe(comm::endpoint dest);

    /**
     * Send completion signal, giving created channel on success or nullptr on failure.
     */
    using completion_signal = boost::signals2::signal<void()>;
    completion_signal on_completed;

protected:
    /**
     * responder calls this to check whether to accept a connection,
     * before actually bothering to verify the initiator's identity.
     * The default implementation always returns true.
     */
    virtual bool is_initiator_acceptable(comm::socket_endpoint const& initiator_ep,
                                         peer_identity const& initiator_eid,
                                         byte_array const& user_data);

    /**
     * responder calls this to create a channel requested by a client.
     * Keys are channel's short-term keys, initiator_ep simply identifies current channel
     * endpoint on the far side.
     * This method can return nullptr to reject the incoming connection.
     */
    virtual socket_channel_uptr create_channel(sodiumpp::secret_key local_short,
                                        sodiumpp::public_key remote_short,
                                        sodiumpp::public_key remote_long,
                                        uia::comm::socket_endpoint const& initiator_ep);
    friend class initiator;

private:
    // Handlers for incoming kex packets
    void got_probe(boost::asio::const_buffer msg, comm::socket_endpoint const& src);
    void got_hello(boost::asio::const_buffer msg, comm::socket_endpoint const& src);
    void got_initiate(boost::asio::const_buffer msg, comm::socket_endpoint const& src);
    void send_cookie(std::string clientKey, comm::socket_endpoint const& src);
};

} // uia::negotiation namespace
