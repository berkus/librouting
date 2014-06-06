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
#include "ssu/server.h"
#include "ssu/host.h"

namespace uia {
namespace routing {

/**
 * Implements regserver protocol as part of SSU stream.
 * This service allows non- or weakly-encrypted connections from clients, which
 * means it must run on (multiple) separate channel(s). @todo How?
 */
class registration_server
{
    friend class internal::registry_record;

    std::shared_ptr<ssu::host> host_;
    ssu::server server_;
    std::vector<ssu::stream> sessions_;

    // Hash of insert challenge cookies and corresponding responses
    std::unordered_map<byte_array, byte_array> chalhash;

    // Hash table to look up records by ID
    std::unordered_map<byte_array, internal::registry_record*> idhash;

    // Hash table to look up records by case-insensitive keyword
    std::unordered_map<std::string,
        std::unordered_set<internal::registry_record*>> keyword_records_;

    // Set of all existing records, for empty searches
    std::unordered_set<internal::registry_record*> all_records_;

    // Break the description into keywords,
    // and either insert or remove the keyword entries for this record.
    void register_keywords(bool insert, internal::registry_record* rec);

    void timeout_record(internal::registry_record* rec);

public:
    registration_server(std::shared_ptr<ssu::host> host);

private:
    void on_incoming_record();
    void do_insert1(byte_array_iwrap<flurry::iarchive>& read, std::shared_ptr<ssu::stream> stream);
    void do_insert2(byte_array_iwrap<flurry::iarchive>& read, std::shared_ptr<ssu::stream> stream);
    void do_lookup(byte_array_iwrap<flurry::iarchive>& read, std::shared_ptr<ssu::stream> stream);
    void do_search(byte_array_iwrap<flurry::iarchive>& read, std::shared_ptr<ssu::stream> stream);
    void do_delete(byte_array_iwrap<flurry::iarchive>& read, std::shared_ptr<ssu::stream> stream);

    void reply_insert1(std::shared_ptr<ssu::stream> stream, const byte_array &idi, const byte_array &nhi);
    void reply_lookup(internal::registry_record *reci, uint32_t replycode,
        const byte_array &idr, internal::registry_record *recr);
    byte_array calc_cookie(const ssu::peer_id &eid, const byte_array &idi,
        const byte_array &nhi);
    internal::registry_record* find_caller(const comm::endpoint &ep,
        const byte_array &idi, const byte_array &nhi);
};

}
}
