#include <unordered_map>
#include <unordered_set>
#include "coordinator.h"
#include "make_unique.h"
#include "link_receiver.h"
#include "logging.h"

using namespace std;

namespace uia {
namespace routing {

constexpr ssu::magic_t routing_magic = 0x00524f55; // 'xROU'

// Private helper class for routing_client_coordinator -
// attaches to our link and dispatches control messages to different clients.
class routing_receiver : public ssu::link_receiver
{
    // Global hash table of active routing_client instances,
    // for dispatching incoming messages based on hashed nonce.
    unordered_map<byte_array, client*> hashed_nonce_clients_;

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
}

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
