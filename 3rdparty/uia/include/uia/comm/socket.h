//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <map>
#include <string>
#include <vector>
#include <memory>
#include <boost/signals2/signal.hpp>
#include "uia/comm/socket_endpoint.h"
#include "uia/comm/socket_host_interface.h"

namespace uia {
namespace comm {

/**
 * Abstract base class for entity connecting two endpoints using some network.
 * Socket manages connection lifetime and maintains the connection status info.
 * Socket dispatches received packets based on marker field in the packet.
 */
class socket : public std::enable_shared_from_this<socket>
{
    /**
     * Host state instance this socket is attached to.
     */
    host_ptr host_{nullptr};

    /**
     * True if this socket is fair game for use by upper level protocols.
     */
    bool active_{false};

public:
    /// uia expresses current socket status as one of three states:
    enum class status
    {
        down,    ///< Definitely appears to be down.
        stalled, ///< Briefly lost connectivity, but may be temporary.
        up       ///< Apparently alive, all is well as far as we know.
    };

    static std::string status_string(status s);

    socket(host_ptr hi)
        : host_(hi)
    {
    }
    virtual ~socket();

    /**
     * Determine whether this socket is active.
     * Only active sockets are returned by socket_host_state::active_sockets().
     * @return true if socket is active.
     */
    inline bool is_active() const { return active_; }

    /**
     * Activate or deactivate this socket.
     * Only active socket are returned by socket_host_state::active_sockets().
     * @param active true if the socket should be marked active.
     */
    void set_active(bool active);

    /**
     * Open the underlying socket, bind it to given endpoint and activate it if successful.
     * @param  ep Endpoint on the local machine to bind the socket to.
     * @return    true if bind successfull, false otherwise.
     */
    virtual bool bind(endpoint ep) = 0;

    /**
     * Unbind and close the underlying socket.
     */
    virtual void unbind() = 0;

    /**
     * Send a packet on this socket.
     * @param ep the destination address to send the packet to.
     * @param data the packet data.
     * @param size the packet size.
     * @return true if send was successful.
     */
    virtual bool send(endpoint ep, char const* data, size_t size) = 0;

    /**
     * Send a packet on this socket.
     * This is an overridden function provided for convenience.
     * @param ep the destination address to send the packet to.
     * @param msg the packet data.
     * @return true if send was successful.
     */
    inline bool send(endpoint ep, byte_array const& msg)
    {
        return send(ep, msg.const_data(), msg.size());
    }

    /**
     * Find all known local endpoints referring to this socket.
     * @return a list of endpoint objects.
     */
    virtual std::vector<endpoint> local_endpoints() = 0;

    /**
     * Return local port number at which this socket is bound on the host.
     * @return local open port number.
     * @fixme this is protocol-dependent and should be encapsulated in endpoint?
     */
    virtual uint16_t local_port() = 0;

    /**
     * Return a description of any error detected on socket operation or an empty string.
     */
    virtual std::string error_string() = 0;

    /**
     * Returns true if this socket provides congestion control
     * when communicating with the specified remote endpoint.
     */
    virtual bool is_congestion_controlled(endpoint const& ep);

    /**
     * For congestion-controlled sockets, returns the number of bytes that may
     * be transmitted now to a particular target endpoint.
     */
    virtual size_t may_transmit(endpoint const& ep);

    using socket_error_signal = boost::signals2::signal<void(std::string)>;
    /**
     * Socket emits this signal when socket operations raise an error.
     */
    socket_error_signal on_socket_error;

protected:
    /**
     * Implementation subclass calls this method with received packets.
     * @param msg the packet received.
     * @param src the source from which the packet arrived.
     */
    void receive(boost::asio::const_buffer msg, socket_endpoint const& src);
};

} // comm namespace
} // uia namespace
