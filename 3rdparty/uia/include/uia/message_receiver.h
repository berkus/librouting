//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "uia/comm/packet_receiver.h"
#include "uia/comm/socket_endpoint.h"
#include <boost/signals2/signal.hpp>

namespace uia::comm {

// Get a message, dispatch to the right channel if exists.
class message_receiver : public uia::comm::packet_receiver
{
    /**
     * Channels working through this receiver at the moment.
     * Receiver does NOT own the channels.
     * Channels are distinguished by sender's short-term public key.
     */
    std::map<std::string, socket_channel_wptr> channels_;

public:
    message_receiver(host_ptr host);

    /**
     * Find channel attached to this socket.
     */
    socket_channel_wptr channel_for(boost::string_ref channel_key);

    /**
     * Bind a new socket_channel to this socket.
     * Called by socket_channel::bind() to register in the table of channels.
     */
    bool bind_channel(std::string channel_key, socket_channel_wptr channel);

    /**
     * Unbind a socket_channel associated with channel short-term key @a channel_key.
     * Called by socket_channel::unbind() to unregister from the table of channels.
     */
    void unbind_channel(std::string channel_key);

    void receive(boost::asio::const_buffer msg, socket_endpoint src) override;
};

} // uia::comm namespace
