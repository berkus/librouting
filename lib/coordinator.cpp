//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2013, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <unordered_map>
#include <unordered_set>
#include "coordinator.h"
#include "make_unique.h"
#include "link_receiver.h"
#include "logging.h"
#include "peer_id.h"
#include "private/regserver_client.h" // @fixme This is tied to regserver now.

using namespace std;
using namespace uia::routing::internal;

namespace uia {
namespace routing {

constexpr ssu::magic_t routing_magic = REG_MAGIC; // 'xROU'

//=====================================================================================================================
// routing_receiver
//=====================================================================================================================

// Private helper class for routing_client_coordinator -
// attaches to our link and dispatches control messages to different clients.
class routing_receiver : public ssu::link_receiver
{
    // Global hash table of active routing_client instances,
    // for dispatching incoming messages based on hashed nonce.
    // 
    // Only regserver_clients can be hashed on the nonce here, since other routing types
    // might not even use it. @todo This will probably need a different implementation.
    unordered_map<byte_array, regserver_client*> hashed_nonce_clients_;

private:
    void receive(byte_array const& msg, ssu::link_endpoint const& src) override;

public:
    routing_receiver(shared_ptr<ssu::host> host);
};

routing_receiver::routing_receiver(shared_ptr<ssu::host> host)
    : ssu::link_receiver(host, routing_magic)
{}

void routing_receiver::receive(byte_array const& msg, ssu::link_endpoint const& src)
{
    logger::debug() << "Routing receiver: received routing packet";
    // Decode the first part of the message
    uint32_t dummy, code;
    byte_array nhi;
    byte_array_iwrap<flurry::iarchive> read(msg);
    read.archive() >> dummy >> code >> nhi;

    // Find the appropriate client
    if (!contains(hashed_nonce_clients_, nhi))
    {
        logger::debug() << this << "received message for nonexistent client";
        return;
    }
    regserver_client *cli = hashed_nonce_clients_[nhi];

    // Make sure this message comes from one of the server's addresses
    if (!contains(cli->addrs, src) or src.port() != cli->srvport) {
        logger::debug() << this << "received message from wrong endpoint" << src;
        return;
    }

    // Dispatch it appropriately
    switch (code) {
    case REG_RESPONSE | REG_INSERT1:
        return cli->gotInsert1Reply(read);
    case REG_RESPONSE | REG_INSERT2:
        return cli->gotInsert2Reply(read);
    case REG_RESPONSE | REG_LOOKUP:
        return cli->gotLookupReply(read, false);
    case REG_RESPONSE | REG_SEARCH:
        return cli->gotSearchReply(read);
    case REG_RESPONSE | REG_DELETE:
        return cli->gotDeleteReply(read);
    case REG_NOTIFY | REG_LOOKUP:
        return cli->gotLookupReply(read, true);
    default:
        logger::debug() << this << "bad message code" << code;
    }
}

//=====================================================================================================================
// coordinator_impl
//=====================================================================================================================

class client_coordinator::coordinator_impl
{
public:
    shared_ptr<ssu::host> host_;
    routing_receiver routing_receiver_;

    // Global registry of every routing_client for this host, so we can
    // produce signals when routing_client are created or destroyed.
    unordered_set<client*> routing_clients_;

public:
    coordinator_impl(shared_ptr<ssu::host> host)
        : host_(host)
        , routing_receiver_(host)
    {}
};

//=====================================================================================================================
// client_coordinator
//=====================================================================================================================

client_coordinator::client_coordinator(ssu::host& host)
    : host_(host)
{}//pimpl_ = stdext::make_unique<coordinator_impl>(host));

std::vector<client*>
client_coordinator::routing_clients() const
{
    return std::vector<client*>();
}

} // routing namespace
} // uia namespace
