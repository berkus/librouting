#pragma once

#include <memory>
#include <vector>
#include <boost/signals2/signal.hpp>

namespace ssu {
class host;
} // ssu namespace

namespace uia {
namespace routing {

class client;

/**
 * Routing client coordinator manages set of routing clients providing information about
 * peer locations and keyword searches.
 */
class routing_client_coordinator
{
    class coordinator_impl;
    std::unique_ptr<coordinator_impl> pimpl_;
public:
    routing_client_coordinator(std::shared_ptr<ssu::host> host);
    std::vector<client*> routing_clients() const;

    typedef boost::signals2::signal<void (client*)> routing_client_signal;
    routing_client_signal on_routing_client_created;
    routing_client_signal on_routing_client_deleted;
};

} // routing namespace
} // uia namespace
