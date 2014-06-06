//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "arsenal/byte_array.h"
#include "arsenal/byte_array_wrap.h"
#include "routing/private/registry_record.h"

namespace uia {
namespace routing {

class registration_server
{
    friend class uia::routing::internal::registry_record;

    // The network code actually duplicates some from ssu::link, maybe this can be refactored.
    std::shared_ptr<ssu::host> host_;
    boost::asio::io_service io_service_;
    boost::asio::ip::udp::socket sock;
    boost::asio::ip::udp::socket sock6;
    boost::asio::streambuf received_buffer;
    comm::endpoint received_from;
    std::string error_string_;

    // XXX should timeout periodically
    byte_array secret;

    // Hash of insert challenge cookies and corresponding responses
    std::unordered_map<byte_array, byte_array> chalhash;

    // Hash table to look up records by ID
    std::unordered_map<byte_array, internal::registry_record*> idhash;

    // Hash table to look up records by case-insensitive keyword
    std::unordered_map<std::string,
        std::unordered_set<internal::registry_record*>> keyword_records_;

    // Set of all existing records, for empty searches
    std::unordered_set<internal::registry_record*> all_records_;

    void prepare_async_receive(boost::asio::ip::udp::socket& sock);

    // Break the description into keywords,
    // and either insert or remove the keyword entries for this record.
    void register_keywords(bool insert, internal::registry_record* rec);

    void timeout_record(internal::registry_record* rec);

public:
    registration_server(std::shared_ptr<ssu::host> host);

    inline void run() { io_service_.run(); }

private:
    void udp_dispatch(byte_array &msg, const comm::endpoint &ep);
    void do_insert1(byte_array_iwrap<flurry::iarchive>& is, const comm::endpoint &ep);
    void do_insert2(byte_array_iwrap<flurry::iarchive>& is, const comm::endpoint &ep);
    void do_lookup(byte_array_iwrap<flurry::iarchive>& is, const comm::endpoint &ep);
    void do_search(byte_array_iwrap<flurry::iarchive>& is, const comm::endpoint &ep);
    void do_delete(byte_array_iwrap<flurry::iarchive>& is, const comm::endpoint& ep);

    void reply_insert1(const comm::endpoint &ep, const byte_array &idi, const byte_array &nhi);
    void reply_lookup(internal::registry_record *reci, uint32_t replycode,
        const byte_array &idr, internal::registry_record *recr);
    byte_array calc_cookie(const comm::endpoint &ep, const byte_array &idi,
        const byte_array &nhi);
    internal::registry_record* find_caller(const comm::endpoint &ep,
        const byte_array &idi, const byte_array &nhi);

private:
    void udp_ready_read(const boost::system::error_code& error, size_t bytes_transferred);
    bool send(const comm::endpoint& ep, byte_array const& msg);
};

} // routing namespace
} // uia namespace
