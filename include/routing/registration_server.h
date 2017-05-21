//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include "arsenal/byte_array.h"
#include "arsenal/byte_array_wrap.h"
#include "uia/peer_identity.h"
// #include "sss/server.h"
#include "uia/host.h"

namespace uia::routing {

/**
 * Implements regserver protocol as part of SSS stream.
 * This service allows non- or weakly-encrypted connections from clients, which
 * means it must run on (multiple) separate channel(s). @todo How?
 */
class registration_server
{
    friend class internal::registry_record;

    std::shared_ptr<uia::host> host_;
    // sss::server server_;
    // std::vector<sss::stream> sessions_;

    // Hash of insert challenge cookies and corresponding responses
    std::unordered_map<arsenal::byte_array, arsenal::byte_array> chalhash;

    // Hash table to look up records by ID
    std::unordered_map<arsenal::byte_array, internal::registry_record*> idhash;

    // Hash table to look up records by case-insensitive keyword
    std::unordered_map<std::string, std::unordered_set<internal::registry_record*>>
        keyword_records_;

    // Set of all existing records, for empty searches
    std::unordered_set<internal::registry_record*> all_records_;

    // Break the description into keywords,
    // and either insert or remove the keyword entries for this record.
    void register_keywords(bool insert, internal::registry_record* rec);

    void timeout_record(internal::registry_record* rec);

public:
    registration_server(std::shared_ptr<uia::host> host);

private:
    void on_incoming_record();
    void do_insert1(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& read,
                    std::shared_ptr<sss::stream> stream);
    void do_insert2(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& read,
                    std::shared_ptr<sss::stream> stream);
    void do_lookup(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& read,
                   std::shared_ptr<sss::stream> stream);
    void do_search(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& read,
                   std::shared_ptr<sss::stream> stream);
    void do_delete(arsenal::byte_array_iwrap<arsenal::flurry::iarchive>& read,
                   std::shared_ptr<sss::stream> stream);

    void reply_insert1(std::shared_ptr<sss::stream> stream,
                       arsenal::byte_array const& idi,
                       arsenal::byte_array const& nhi);
    void reply_lookup(internal::registry_record* reci,
                      uint32_t replycode,
                      arsenal::byte_array const& idr,
                      internal::registry_record* recr);
    arsenal::byte_array calc_cookie(uia::peer_identity const& eid,
                                    arsenal::byte_array const& idi,
                                    arsenal::byte_array const& nhi);
    internal::registry_record* find_caller(comm::endpoint const& ep,
                                           arsenal::byte_array const& idi,
                                           arsenal::byte_array const& nhi);
};

} // uia::routing namespace
