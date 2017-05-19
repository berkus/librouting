//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "arsenal/logging.h"
#include "uia/comm/socket_endpoint.h"
#include "uia/comm/socket.h"

namespace uia {
namespace comm {

//=================================================================================================
// socket_endpoint
//=================================================================================================

bool
socket_endpoint::send(const char *data, int size) const
{
    if (auto s = socket_.lock()) {
        return s->send(*this, data, size);
    }
    logger::debug() << "Trying to send on a nonexistent link";
    return false;
}

} // comm namespace
} // uia namespace
