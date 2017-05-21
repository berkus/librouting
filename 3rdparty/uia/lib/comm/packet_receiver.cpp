//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/comm/packet_receiver.h"
#include "uia/comm/socket_host_interface.h"
#include "uia/host.h"
#include <boost/log/trivial.hpp>

using namespace std;

namespace uia {
namespace comm {

//=================================================================================================
// packet_receiver
//=================================================================================================

void
packet_receiver::bind(uint64_t magic)
{
    // assert(!is_bound()); @todo Make receiver possible to bind to multiple magic values...
    assert(magic != 0);
    assert(!host_->has_receiver_for(magic));

    magic_ = magic;
    BOOST_LOG_TRIVIAL(debug) << "Link receiver " << this << " binds for magic " << hex << magic_;
    host_->bind_receiver(magic_, shared_from_this());
}

void
packet_receiver::unbind()
{
    if (is_bound())
    {
        BOOST_LOG_TRIVIAL(debug) << "Link receiver " << this << " unbinds magic " << hex << magic_;
        host_->unbind_receiver(magic_);
        // make it possible to unbind from multiple magic values too...
        magic_ = 0;
    }
}

} // comm namespace
} // uia namespace
