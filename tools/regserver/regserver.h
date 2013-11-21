//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2013, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "byte_array.h"
#include "byte_array_wrap.h"
#include "link.h" // @todo move the link classes to comm::link
#include "timer.h" // @todo move ssu::async to async

namespace uia {
namespace routing {

class registration_server;

namespace internal {

// We maintain a registry_record for each registered client.
// For memory space efficiency, we keep info blocks in binary form
// and only break them out into a client_profile object when we need to.
// Private helper class for registration_server.
class registry_record
{
    friend class uia::routing::registration_server;

    registration_server * const srv;
    const byte_array id;
    const byte_array nhi;
    const ssu::endpoint ep;
    const byte_array info;
    ssu::async::timer timer_;

    registry_record(registration_server *srv, const byte_array &id, const byte_array &nhi,
        const ssu::endpoint &ep, const byte_array &info);
    ~registry_record();

    // Break the description into keywords,
    // and either insert or remove the keyword entries for this record.
    void regKeywords(bool insert);

    void timerEvent();
};

} // internal namespace

class registration_server
{
    friend class uia::routing::internal::registry_record;

    // The network code actually duplicates some from ssu::link, maybe this can be refactored.
    std::shared_ptr<ssu::host> host_;
    boost::asio::io_service io_service_;
    boost::asio::ip::udp::socket sock;
    boost::asio::ip::udp::socket sock6;
    boost::asio::streambuf received_buffer;
    ssu::endpoint received_from;
    std::string error_string_;

    // XX should timeout periodically
    byte_array secret;

    // Hash of insert challenge cookies and corresponding responses
    std::unordered_map<byte_array,byte_array> chalhash;

    // Hash table to look up records by ID
    std::unordered_map<byte_array,internal::registry_record*> idhash;

    // Hash table to look up records by case-insensitive keyword
    std::unordered_map<std::string, std::unordered_set<internal::registry_record*> > kwhash;

    // Set of all existing records, for empty searches
    std::unordered_set<internal::registry_record*> all_records_;

    void prepare_async_receive(boost::asio::ip::udp::socket& sock);


public:
    registration_server(std::shared_ptr<ssu::host> host);

    inline void run() { io_service_.run(); }

private:
    void udp_dispatch(byte_array &msg, const ssu::endpoint &ep);
    void do_insert1(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint &ep);
    void do_insert2(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint &ep);
    void do_lookup(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint &ep);
    void do_search(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint &ep);
    void do_delete(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint& ep);

    void reply_insert1(const ssu::endpoint &ep, const byte_array &idi, const byte_array &nhi);
    void reply_lookup(internal::registry_record *reci, uint32_t replycode,
            const byte_array &idr, internal::registry_record *recr);
    byte_array calc_cookie(const ssu::endpoint &ep, const byte_array &idi,
                const byte_array &nhi);
    internal::registry_record *find_caller(const ssu::endpoint &ep, const byte_array &idi,
                const byte_array &nhi);

private:
    void udp_ready_read(const boost::system::error_code& error, size_t bytes_transferred);
    bool send(const ssu::endpoint& ep, byte_array const& msg);
};

} // routing namespace
} // uia namespace
