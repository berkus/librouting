//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "arsenal/logging.h"
#include "uia/peer_identity.h"
#include "routing/private/registry_record.h"
#include "routing/registration_server.h"

namespace uia {
namespace routing {
namespace internal {

constexpr uint32_t registry_record::timeout_seconds;

//=================================================================================================
// registry_record implementation
//=================================================================================================

registry_record::registry_record(registration_server& srv,
                                 const byte_array& id,
                                 const byte_array& nhi,
                                 const uia::comm::endpoint& ep,
                                 const byte_array& info)
    : srv(srv)
    , id(id)
    , nhi(nhi)
    , ep(ep)
    , profile_info_(info)
    , timer_(srv.host_.get())
{
    logger::debug() << "Registering record for " << uia::peer_identity(id) << " at " << ep;

    // Set the record's timeout
    timer_.on_timeout.connect([this, &srv](bool) { srv.timeout_record(this); });
    timer_.start(boost::posix_time::seconds(timeout_seconds));
}

registry_record::~registry_record()
{
    logger::debug() << "~registry_record: deleting record for " << uia::peer_identity(id);
}

} // internal namespace
} // routing namespace
} // uia namespace
