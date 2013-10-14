#include <unordered_map>
#include <unordered_set>
#include "coordinator.h"
#include "link_receiver.h"

using namespace std;

namespace uia {
namespace routing {

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


class routing_client_coordinator::coordinator_impl
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

} // routing namespace
} // uia namespace
