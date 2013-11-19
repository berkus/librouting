//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2013, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <boost/signals2/signal.hpp>
#include "peer_id.h"

namespace uia {
namespace routing {

class client_profile;

/**
 * Routing client represents the client side of the routing libraries.
 * It provides notifications about found peer endpoints and allows to initiate peer searches.
 */
class client
{
    // class client_impl;
    // std::unique_ptr<client_impl> pimpl_;

public:
    virtual ~client() {}

    virtual /*shared_ptr<*/ssu::host* get_host() = 0;

    // Get the metadata about this client.
    std::shared_ptr<client_profile> profile() const;
    // Set the metadata about this client.
    void set_profile(std::shared_ptr<client_profile> profile);

    /**
     * Return some name of the routing client.
     * In case of rendezvous server it may be server IP or DNS name.
     */
    virtual std::string name() const = 0;

    /**
     * Return true if routing_client is ready to perform peer lookups.
     */
    virtual bool is_ready() const = 0;

    // Request information about a specific ID.
    // Will send an on_lookup_done() signal when the request completes.
    // If 'notify', ask whoever found the ID to notify the target as well.
    virtual void lookup(ssu::peer_id const& id, bool notify = false) = 0;

    // Search for IDs of clients with metadata matching a search string.
    // Will send an on_search_done() signal when the request completes.
    virtual void search(std::string const& text) = 0;

    typedef boost::signals2::signal<void (void)> ready_signal;
    ready_signal on_ready; /* Client is ready to resolve EIDs */
    ready_signal on_disconnected; /* Client is not ready anymore */

    typedef boost::signals2::signal<void (ssu::peer_id const& /* target peer */,
        ssu::endpoint const& /* endpoint found for this peer */,
        client_profile const& /* peer's profile data */)>
        lookup_signal;
    typedef boost::signals2::signal<void (ssu::peer_id const& /* target peer */)>
        lookup_fail_signal;

    /**
     * Emitted when lookup request returns some results.
     */
    lookup_signal on_lookup_done;
    /**
     * Emitted when lookup request fails without returning results or routing client disconnects.
     */
    lookup_fail_signal on_lookup_failed;
    /**
     * Emitted when somebody else's lookup request found our metadata.
     */
    lookup_signal on_lookup_notify;

    typedef boost::signals2::signal<void (std::string const& /*search term*/,
        std::vector<ssu::peer_id> const& /* peers matching this term */, 
        bool /*last result received*/)>
        search_signal;

    /**
     * Emitted when search() found some records.
     */
    search_signal on_search_done;

    inline void search_failed(std::string const& term) {
        on_search_done(term, std::vector<ssu::peer_id>(), true);
    }
};

} // routing namespace
} // uia namespace
