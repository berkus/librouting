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
#include <unordered_map>
#include <unordered_set>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/streambuf.hpp>

namespace uia::routing {

class registration_server
{
    friend class uia::routing::internal::registry_record;

    // The network code actually duplicates some from comm::socket, maybe this can be refactored.
    std::shared_ptr<uia::host> host_;
    boost::asio::io_service io_service_;
    boost::asio::ip::udp::socket sock;
    boost::asio::ip::udp::socket sock6;
    boost::asio::streambuf received_buffer;
    uia::comm::endpoint received_from;
    std::string error_string_;

    // XXX should timeout periodically
    arsenal::byte_array secret;

    // Hash of insert challenge cookies and corresponding responses
    std::unordered_map<arsenal::byte_array, arsenal::byte_array> chalhash;

    // Hash table to look up records by ID
    std::unordered_map<arsenal::byte_array, internal::registry_record*> idhash;

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
    registration_server(std::shared_ptr<uia::host> host);

    inline void run() { io_service_.run(); }

private:
    void udp_dispatch(arsenal::byte_array& msg, comm::endpoint const& ep);
    void do_insert1(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& is,
                    comm::endpoint const& ep);
    void do_insert2(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& is,
                    comm::endpoint const& ep);
    void do_lookup(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& is,
                   comm::endpoint const& ep);
    void do_search(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& is,
                   comm::endpoint const& ep);
    void do_delete(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& is,
                   comm::endpoint const& ep);

    void reply_insert1(comm::endpoint const& ep,
                       arsenal::byte_array const& idi,
                       arsenal::byte_array const& nhi);
    void reply_lookup(internal::registry_record* reci,
                      uint32_t replycode,
                      arsenal::byte_array const& idr,
                      internal::registry_record* recr);
    arsenal::byte_array calc_cookie(comm::endpoint const& ep,
                                    arsenal::byte_array const& idi,
                                    arsenal::byte_array const& nhi);
    internal::registry_record* find_caller(comm::endpoint const& ep,
                                           arsenal::byte_array const& idi,
                                           arsenal::byte_array const& nhi);

private:
    void udp_ready_read(boost::system::error_code const& error, size_t bytes_transferred);
    bool send(comm::endpoint const& ep, arsenal::byte_array const& msg);
};

} // uia::routing namespace
