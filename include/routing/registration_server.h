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

    void timeout_record(internal::registry_record* rec);

public:
    registration_server(std::shared_ptr<ssu::host> host);

private:
    void on_incoming_record();

    void send_notify();
    void send_response();
};

}
}
