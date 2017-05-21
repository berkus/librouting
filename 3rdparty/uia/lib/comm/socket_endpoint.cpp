//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <boost/log/trivial.hpp>
#include "uia/comm/socket_endpoint.h"
#include "uia/comm/socket.h"

namespace uia::comm {

//=================================================================================================
// socket_endpoint
//=================================================================================================

bool
socket_endpoint::send(const char *data, int size) const
{
    if (auto s = socket_.lock()) {
        return s->send(*this, data, size);
    }
    BOOST_LOG_TRIVIAL(debug) << "Trying to send on a nonexistent link";
    return false;
}

} // uia::comm namespace
