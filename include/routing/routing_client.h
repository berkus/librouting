//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <boost/signals2/signal.hpp>
#include "uia/peer_identity.h"
#include "sss/host.h"

namespace uia::routing {

class client_profile;
class client;

/* Helper base class to keep on_destroyed still intact in derived class destructor. */
struct client_destroyer
{
    using destroyed_signal = boost::signals2::signal<void(client*)>;
    destroyed_signal on_destroyed;
};

/**
 * Routing client represents the client side of the routing libraries.
 * It provides notifications about found peer endpoints and allows to initiate peer searches.
 */
class client : public client_destroyer
{
public:
    virtual ~client() { on_destroyed(this); }

    virtual /*shared_ptr<*/ sss::host* get_host() = 0;

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
    virtual void lookup(peer_identity const& id, bool notify = false) = 0;

    // Search for IDs of clients with metadata matching a search string.
    // Will send an on_search_done() signal when the request completes.
    virtual void search(std::string const& text) = 0;

    using ready_signal = boost::signals2::signal<void(void)>;
    ready_signal on_ready;        /* Client is ready to resolve EIDs */
    ready_signal on_disconnected; /* Client is not ready anymore */

    using lookup_signal =
        boost::signals2::signal<void(peer_identity const& /* target peer */,
                                     uia::comm::endpoint const& /* endpoint found for this peer */,
                                     client_profile const& /* peer's profile data */)>;
    using lookup_fail_signal =
        boost::signals2::signal<void(peer_identity const& /* target peer */)>;

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

    using search_signal = boost::signals2::signal<void(
        std::string const& /*search term*/,
        std::vector<peer_identity> const& /* peers matching this term */,
        bool /*last result received*/)>;

    /**
     * Emitted when search() found some records.
     */
    search_signal on_search_done;

    inline void search_failed(std::string const& term)
    {
        on_search_done(term, std::vector<peer_identity>(), true);
    }
};

} // uia::routing namespace
