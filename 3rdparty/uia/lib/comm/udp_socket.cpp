//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/comm/udp_socket.h"
#include "uia/comm/platform.h"
#include "uia/host.h" //for get_io_service() on host
#include <boost/log/trivial.hpp>
#include <memory>

using namespace std;
using namespace boost;
using namespace boost::asio;

constexpr size_t MAX_PACKET_SIZE = 1280;

namespace uia::comm {

//=================================================================================================
// helper function
//=================================================================================================

bool
bind_socket(ip::udp::socket& sock, endpoint ep, std::string& error_string)
{
    system::error_code ec;
    sock.open(ep.protocol(), ec);
    if (ec) {
        error_string = ec.message();
        BOOST_LOG_TRIVIAL(warning) << "udp socket open error - " << ec.message();
        return false;
    }
    sock.bind(ep, ec);
    if (ec) {
        error_string = ec.message();
        BOOST_LOG_TRIVIAL(warning) << "udp socket bind error - " << ec.message();
        return false;
    }
    error_string = "";
    return true;
}

//=================================================================================================
// udp_request
//=================================================================================================

struct udp_request : std::enable_shared_from_this<udp_request>
{
    udp_socket* socket_;
    /**
     * Buffer holding the received packet.
     * @todo Replace with a buffer pool.
     */
    asio::streambuf received_buffer_;
    /**
     * Endpoint from which we've received the packet.
     */
    socket_endpoint received_from_;

    udp_request(udp_socket* socket)
        : socket_(socket)
        , received_buffer_(MAX_PACKET_SIZE)
    {
    }

    void handle_request(system::error_code const& error, size_t bytes_transferred);
};

// Completely asynchronous packet handler.
void
udp_request::handle_request(system::error_code const& error, size_t bytes_transferred)
{
    if (!error) {
        BOOST_LOG_TRIVIAL(debug) << "Received " << dec << bytes_transferred << " bytes via UDP from "
                        << received_from_ << " on socket " << socket_;
        received_buffer_.commit(bytes_transferred);
        socket_->receive(asio::buffer(received_buffer_.data()), received_from_);
    } else {
        BOOST_LOG_TRIVIAL(warning) << "UDP read error - " << error.message();
        socket_->set_error(error.message());
    }
}

using udp_request_ptr = std::shared_ptr<udp_request>;

//=================================================================================================
// udp_socket
//=================================================================================================

// @fixme We only need io_service, so just pass that in?
udp_socket::udp_socket(uia::host_ptr host)
    : socket(host)
    , udp_socket_(host->get_io_service())
    , strand_(host->get_io_service())
{
}

/**
 * See http://stackoverflow.com/questions/12794107/why-do-i-need-strand-per-connection
 * Always run prepare_async_receive() through a strand to make this operation thread safe.
 *
 * See http://stackoverflow.com/questions/26703583/boostasio-async-receive-from-udp-endpoint
 * for usage of udp_request.
 */
void
udp_socket::prepare_async_receive()
{
    auto request = make_shared<udp_request>(this); // @fixme Extraneous memory allocation...

    udp_socket_.async_receive_from(
        buffer(request->received_buffer_.prepare(MAX_PACKET_SIZE)),
        request->received_from_,
        strand_.wrap(boost::bind(&udp_socket::udp_ready_read,
                                 this,
                                 request,
                                 asio::placeholders::error,
                                 asio::placeholders::bytes_transferred)));
}

void
udp_socket::udp_ready_read(udp_request_ptr request,
                           system::error_code const& error,
                           size_t bytes_transferred)
{
    // now, handle the current request on any available pool thread
    udp_socket_.get_io_service().post(
        boost::bind(&udp_request::handle_request, request, error, bytes_transferred));

    // immediately accept new datagrams
    prepare_async_receive();
}

vector<endpoint>
udp_socket::local_endpoints()
{
    vector<endpoint> result{udp_socket_.local_endpoint()};
    auto addresses = platform::local_endpoints();
    auto port = local_port();
    for (auto v : addresses) {
        v.port(port);
        result.emplace_back(v);
    }
    return result;
}

uint16_t
udp_socket::local_port()
{
    return udp_socket_.local_endpoint().port();
}

bool
udp_socket::bind(endpoint ep)
{
    BOOST_LOG_TRIVIAL(debug) << "udp_socket bind on endpoint " << ep;
    if (!bind_socket(udp_socket_, ep, error_string_))
        return false;
    BOOST_LOG_TRIVIAL(debug) << "Bound udp_socket on " << ep;
    // once bound, can start receiving datagrams.
    prepare_async_receive();
    set_active(true);
    return true;
}

void
udp_socket::unbind()
{
    BOOST_LOG_TRIVIAL(debug) << "udp_socket unbind";
    udp_socket_.shutdown(ip::udp::socket::shutdown_both);
    udp_socket_.close();
    set_active(false);
}

void
udp_socket::handle_sent(endpoint const& ep,
                        system::error_code const& error,
                        size_t bytes_transferred)
{
    if (error) {
        BOOST_LOG_TRIVIAL(warning) << "UDP write error - " << error.message();
        set_error(error.message());
    }
}

// @todo manage memory being sent...
bool
udp_socket::send(endpoint ep, char const* data, size_t size)
{
    udp_socket_.async_send_to(buffer(data, size),
                              ep,
                              strand_.wrap(boost::bind(&udp_socket::handle_sent,
                                                       this,
                                                       ep,
                                                       asio::placeholders::error,
                                                       asio::placeholders::bytes_transferred)));
    return true;
}

} // uia::comm namespace
