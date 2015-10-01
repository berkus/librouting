//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <unordered_map>
#include <unordered_set>
#include "arsenal/logging.h"
#include "arsenal/algorithm.h"
#include "arsenal/make_unique.h"
#include "uia/peer_identity.h"
#include "comm/packet_receiver.h"
#include "routing/coordinator.h"
#include "routing/private/regserver_client.h" // @fixme This is tied to regserver now.

using namespace std;
using namespace uia::routing::internal;

namespace uia {
namespace routing {

//=====================================================================================================================
// routing_receiver
//=====================================================================================================================

// Private helper class for routing_client_coordinator -
// attaches to our link and dispatches control messages to different clients.
class routing_receiver : public comm::packet_receiver
{
    // Global hash table of active routing_client instances,
    // for dispatching incoming messages based on hashed nonce.
    //
    // Only regserver_clients can be hashed on the nonce here, since other routing types
    // might not even use it. @todo This will probably need a different implementation.
    unordered_map<byte_array, client*> hashed_nonce_clients_;

private:
    void receive(boost::asio::const_buffer msg, uia::comm::socket_endpoint const& src) override;

public:
    routing_receiver(shared_ptr<sss::host> host);

    inline void insert_nonce(byte_array const& nonce, client* c)
    {
        hashed_nonce_clients_.insert(make_pair(nonce, c));
    }

    // Remove any nonce we may have registered in the nhihash.
    inline void clear_nonce(byte_array const& nonce) { hashed_nonce_clients_.erase(nonce); }
};

routing_receiver::routing_receiver(shared_ptr<sss::host> host)
    : comm::packet_receiver(host.get())
{
    logger::debug() << "Routing receiver created";
}

void
routing_receiver::receive(boost::asio::const_buffer msg, uia::comm::socket_endpoint const& src)
{
    logger::debug() << "Routing receiver: received routing packet";
    // Decode the first part of the message
    // uint32_t code;
    byte_array nhi;
    // byte_array_iwrap<flurry::iarchive> read(msg);
    // read.archive().skip_raw_data(4);
    // read.archive() >> code >> nhi;

    // Find the appropriate client
    if (!contains(hashed_nonce_clients_, nhi)) {
        logger::debug() << "Received message for nonexistent client";
        return;
    }
    regserver_client* cli = static_cast<regserver_client*>(hashed_nonce_clients_[nhi]);

    // Make sure this message comes from one of the server's addresses
    if (!contains(cli->addrs, src) or src.port() != cli->srvport) {
        logger::debug() << "Received message from wrong endpoint " << src;
        return;
    }

    // Dispatch it appropriately
    // switch (code) {
    //     case REG_RESPONSE | REG_INSERT1: return cli->got_insert1_reply(read);
    //     case REG_RESPONSE | REG_INSERT2: return cli->got_insert2_reply(read);
    //     case REG_RESPONSE | REG_LOOKUP: return cli->got_lookup_reply(read, false);
    //     case REG_RESPONSE | REG_SEARCH: return cli->got_search_reply(read);
    //     case REG_RESPONSE | REG_DELETE: return cli->got_delete_reply(read);
    //     case REG_NOTIFY | REG_LOOKUP:
    //         return cli->got_lookup_reply(read, true);
    //     // @todo Add regserver REG_REQUEST handling for implementing regserver directly inside
    //     // client.
    //     default: logger::debug() << this << "bad message code" << code;
    // }
}

//=====================================================================================================================
// coordinator_impl
//=====================================================================================================================

class client_coordinator::coordinator_impl
{
public:
    sss::host& host_;
    routing_receiver routing_receiver_;

    // Global registry of every routing_client for this host, so we can
    // produce signals when routing_client are created or destroyed.
    unordered_set<client*> routing_clients_;

public:
    coordinator_impl(shared_ptr<sss::host> host)
        : host_(*host.get())
        , routing_receiver_(host)
    {
    }
};

//=====================================================================================================================
// client_coordinator
//=====================================================================================================================

client_coordinator::client_coordinator(shared_ptr<sss::host> host)
    : host_(*host.get())
    , pimpl_(stdext::make_unique<coordinator_impl>(host))
{
}

std::vector<client*>
client_coordinator::routing_clients() const
{
    return set_to_vector(pimpl_->routing_clients_);
}

void
client_coordinator::add_routing_client(client* c)
{
    pimpl_->routing_clients_.insert(c);
}

void
client_coordinator::remove_routing_client(client* c)
{
    pimpl_->routing_clients_.erase(c);
}

void
client_coordinator::insert_nonce(byte_array const& nonce, client* c)
{
    add_routing_client(c);
    pimpl_->routing_receiver_.insert_nonce(nonce, c);
}

void
client_coordinator::clear_nonce(byte_array const& nonce)
{
    pimpl_->routing_receiver_.clear_nonce(nonce);
}

} // routing namespace
} // uia namespace
