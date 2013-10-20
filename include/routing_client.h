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

namespace uia {
namespace routing {

class client_profile;

/**
 * Routing client represents the client side of the routing libraries.
 * It provides notifications about found peer endpoints and allows to initiate peer searches.
 */
class client
{
    class client_impl;
    std::unique_ptr<client_impl> pimpl_;

public:
    // Get the metadata about this client.
    std::shared_ptr<client_profile> profile() const;
    // Set the metadata about this client.
    void set_profile(std::shared_ptr<client_profile> profile);

    // Request information about a specific ID.
    // Will send an on_lookup_done() signal when the request completes.
    // If 'notify', ask whoever found the ID to notify the target as well.
    void lookup(ssu::peer_id const& id, bool notify = false);

    // Search for IDs of clients with metadata matching a search string.
    // Will send an on_search_done() signal when the request completes.
    void search(std::string const& text);

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
