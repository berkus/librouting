//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/channels/channel_host_state.h"
#include "uia/negotiation/constants.h"
#include "uia/message_receiver.h"
#include <boost/log/trivial.hpp>

using namespace std;

namespace uia {
namespace comm {

void
channel_host_state::register_receiver()
{
    // Add MESSAGE receiver
    receiver_ = std::make_shared<message_receiver>(get_host());
    assert(receiver_);
    bind_receiver(magic::message_packet::value, receiver_);
}

packet_receiver_wptr
channel_host_state::receiver_for(packet_magic_t magic)
{
    auto it = receivers_.find(magic);
    if (it == receivers_.end()) {
        BOOST_LOG_TRIVIAL(debug) << "Receiver not found looking for magic " << hex << magic;
        return packet_receiver_wptr();
    }
    return it->second;
}

} // comm namespace
} // uia namespace
