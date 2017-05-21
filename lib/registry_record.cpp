//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <boost/log/trivial.hpp>
#include "uia/peer_identity.h"
#include "routing/private/registry_record.h"
#include "routing/registration_server.h"
#include <chrono>

namespace uia::routing::internal {

static constexpr auto timeout = (1*60*60);//std::chrono::hours(1); // Records last 1 hour

//=================================================================================================
// registry_record implementation
//=================================================================================================

registry_record::registry_record(registration_server& srv,
                                 const byte_array& id,
                                 const byte_array& nhi,
                                 const uia::comm::endpoint& ep,
                                 byte_array const& info)
    : srv(srv)
    , id(id)
    , nhi(nhi)
    , ep(ep)
    , profile_info_(info)
    , timer_(srv.host_.get())
{
    BOOST_LOG_TRIVIAL(debug) << "Registering record for " << uia::peer_identity(id.as_string()) << " at " << ep;

    // Set the record's timeout
    timer_.on_timeout.connect([this, &srv](bool) { srv.timeout_record(this); });
    timer_.start(boost::posix_time::seconds(timeout));
}

registry_record::~registry_record()
{
    BOOST_LOG_TRIVIAL(debug) << "~registry_record: deleting record for " << uia::peer_identity(id.as_string());
}

} // uia::routing::internal namespace
