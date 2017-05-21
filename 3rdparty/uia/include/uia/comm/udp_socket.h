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
#include <boost/asio.hpp>
#include "uia/comm/socket.h"
#include "uia/forward_ptrs.h"
#include "arsenal/settings_provider.h"

namespace uia {
namespace comm {

struct udp_request;

/**
 * Class for UDP connection between two endpoints.
 * Multiplexes between channel-setup/key exchange traffic (which goes to sss::kex_responder)
 * and per-channel data traffic (which goes to sss::channel).
 */
class udp_socket : public socket
{
    /**
     * Underlying socket.
     */
    boost::asio::ip::udp::socket udp_socket_;
    /**
     * Network activity execution queue.
     */
    boost::asio::strand strand_;
    /**
     * Socket error status.
     */
    std::string error_string_;

    friend struct udp_request; // Access to receive() only.

public:
    udp_socket(host_ptr host);

    /**
     * Bind this UDP socket to a port and activate it if successful.
     * @param  ep Local endpoint to bind to.
     * @return    true if bind successful and socket has been activated, false otherwise.
     */
    bool bind(endpoint ep) override;
    void unbind() override;

    /**
     * Send a packet on this UDP socket.
     * @param  ep   Target endpoint - intended receiver of the packet.
     * @param  data Packet data.
     * @param  size Packet size.
     * @return true If send was successful, i.e. the packet has been sent. It does not say anything
     *              about the reception of the packet on the other side, if it was ever delivered
     *              or accepted.
     */
    bool send(endpoint ep, char const* data, size_t size) override;
    using socket::send;

    /**
     * Return a description of any error detected on bind() or send().
     */
    inline std::string error_string() override { return error_string_; }

    inline void set_error(std::string error)
    {
        error_string_ = error;
        on_socket_error(error);
    }

    /**
     * Return all known local endpoints referring to this socket.
     */
    std::vector<endpoint> local_endpoints() override;

    uint16_t local_port() override;

private:
    void prepare_async_receive();
    void udp_ready_read(std::shared_ptr<udp_request> request,
                        boost::system::error_code const& error,
                        size_t bytes_transferred);
    void handle_sent(endpoint const& ep,
                     boost::system::error_code const& error,
                     size_t bytes_transferred);
};

/**
 * Helper function to bind a passed in socket to a given ep and set the error string to
 * error message if any.
 *
 * @param  sock         Reference to UDP socket to open and bind.
 * @param  ep           Endpoint to bind to. Can be ipv4 or ipv6.
 * @param  error_string Output string to set if error occured.
 * @return              true if successful, false if any error occured. Error string is set then.
 */
bool bind_socket(boost::asio::ip::udp::socket& sock, endpoint ep, std::string& error_string);

} // comm namespace
} // uia namespace
