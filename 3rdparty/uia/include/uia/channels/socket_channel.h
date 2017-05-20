//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <sodiumpp/sodiumpp.h>
#include "uia/comm/socket.h"
#include "uia/comm/socket_endpoint.h"
#include "uia/forward_ptrs.h"

namespace uia {

/**
 * Base class for socket-based channels,
 * for dispatching received packets based on endpoint and channel number.
 * May be used as an abstract base by overriding the receive() method,
 * or used as a concrete class by connecting to the on_received signal.
 */
class socket_channel : public std::enable_shared_from_this<socket_channel>
{
    uia::comm::socket_wptr socket_;  ///< Socket we're currently bound to, if any.
    uia::comm::endpoint remote_ep_;  ///< Endpoint of the remote side.
    // @todo change these to krypto::secret_key and krypto::public_key
    sodiumpp::secret_key local_key_;///< Near end short-term secret key.
    sodiumpp::public_key remote_key_;///< Far end short-term public key.
    bool active_{false};             ///< True if we're sending and accepting packets.

    /**
     * Encode and authenticate data packet.
     * @param  pkt    Packet to encode.
     * @return        Encoded and authenticated packet.
     */
    arsenal::byte_array transmit_encode(boost::asio::mutable_buffer pkt);
    /**
     * Decode packet.
     * @param  in     Incoming packet.
     * @param  out    Decrypted packet.
     * @return        true if packet is verified to be authentic and decoded.
     */
    bool receive_decode(boost::asio::const_buffer in, arsenal::byte_array& out);

public:
    socket_channel(sodiumpp::secret_key local_short,
                          sodiumpp::public_key remote_short,
                          uia::comm::socket_endpoint const& responder_ep);
    inline virtual ~socket_channel() { unbind(); }

    /**
     * Start the channel.
     * @param initiate Initiate the key exchange using kex_initiator.
     */
    inline virtual void start()
    {
        // assert(!remote_channel_key_.empty());
        active_ = true;
    }

    /**
     * Stop the channel.
     */
    inline virtual void stop() { active_ = false; }

    inline bool is_active() const { return active_; }

    inline bool is_bound() const { return socket_.lock() != nullptr; }

    /**
     * Test whether underlying socket is already congestion controlled.
     */
    inline bool is_congestion_controlled()
    {
        if (auto sock = socket_.lock()) {
            return sock->is_congestion_controlled(remote_ep_);
        }
        return false;
    }

    /**
     * Return the remote endpoint we're bound to, if any.
     */
    inline uia::comm::socket_endpoint remote_endpoint() const
    {
        return uia::comm::socket_endpoint(socket_, remote_ep_);
    }

    /**
     * Set up for communication with specified remote endpoint,
     * binding to a particular local channel key.
     * @returns false if the channel is already in use and cannot be bound to.
     *
     * @fixme Channel key here is the peer's public key, and this binding should not be to the
     * socket but to the message_receiver.
     * It also should skip remote EP entirely and bind based only on channel key.
     * Sending should be directed to EP from which _the latest_ packet was received from this
     * peer. And as such a lower-level must maintain this channelkey<->ep mapping somewhere.
     * (Current implementation is largely invalid because it uses remote_ep_ as peer address).
     */
    // bool bind(socket::weak_ptr socket, endpoint const& remote_ep, std::string channel_key);

    // inline bool bind(socket_endpoint const& remote_ep, std::string channel_key) {
    //     return bind(remote_ep.socket(), remote_ep, channel_key);
    // }

    /**
     * Stop channel and unbind from any currently bound remote endpoint.
     * This removes cached local and remote short-term public keys, making channel
     * unable to decode and further received packets with these keys. This provides
     * forward secrecy.
     * After unbind() is called no communication may happen over the channel and a new one
     * must be established to continue communication.
     */
    void unbind();

    /**
     * Return current local channel number.
     */
    inline std::string local_channel() const { return local_key_.pk.get(); }

    /**
     * Return current remote channel number.
     */
    inline std::string remote_channel() const { return remote_key_.get(); }

    /**
     * Receive a network packet msg from endpoint src.
     * Implementations may override this function or simply connect to on_received() signal.
     * Default implementation simply emits on_received() signal.
     * @param msg A received network packet
     * @param src Sender endpoint
     */
    inline virtual void receive(boost::asio::const_buffer msg,
                                uia::comm::socket_endpoint src)
    {
        on_received(msg, src);
    }

    /** @name Signals. */
    /**@{*/
    // Provide access to signal types for clients
    using received_signal =
        boost::signals2::signal<void(boost::asio::const_buffer, uia::comm::socket_endpoint const&)>;
    using ready_transmit_signal = boost::signals2::signal<void()>;

    /**
     * Signalled when channel receives a packet.
     */
    received_signal on_received;
    /**
     * Signalled when channel congestion control may allow new transmission.
     */
    ready_transmit_signal on_ready_transmit;
    /**@}*/

// protected: @fixme
    /**
     * When the underlying socket is already congestion-controlled, this function returns
     * the number of bytes that channel control says we may transmit now, 0 if none.
     */
    virtual size_t may_transmit();

    /**
     * Send a network packet and return success status.
     * @param  pkt Network packet to send
     * @return     true if socket call succeeded. The packet may actually have not been sent.
     */
    inline bool send(arsenal::byte_array const& pkt) const
    {
        assert(active_);
        if (auto s = socket_.lock()) {
            return s->send(remote_ep_, pkt);
        }
        return false;
    }

    void send_message(std::string payload);
};

} // uia namespace

