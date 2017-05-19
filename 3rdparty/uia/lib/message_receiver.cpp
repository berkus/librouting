//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/message_receiver.h"
#include "uia/channels/socket_channel.h"
#include <boost/utility/string_ref.hpp>

using namespace std;

namespace uia {
namespace comm {

message_receiver::message_receiver(host_ptr host)
    : packet_receiver(host)
{}

socket_channel_wptr
message_receiver::channel_for(boost::string_ref channel_key)
{
    std::string key{channel_key.begin(), channel_key.end()}; // DUH!

    if (!contains(channels_, key)) {
        return socket_channel_ptr();
    }
    return channels_[key];
}

bool
message_receiver::bind_channel(string channel_key, socket_channel_wptr lc)
{
    assert(channel_for(channel_key).lock() == nullptr);
    channels_[channel_key] = lc;
    return true;
}

void
message_receiver::unbind_channel(string channel_key)
{
    channels_.erase(channel_key);
}


inline boost::string_ref
string_view(boost::asio::const_buffer buf, size_t start_offset, size_t count = boost::string_ref::npos)
{
    const char* b = boost::asio::buffer_cast<const char*>(buf);
    return boost::string_ref(b, boost::asio::buffer_size(buf)).substr(start_offset, count);
}

void
message_receiver::receive(boost::asio::const_buffer msg, socket_endpoint src)
{
    if (auto channel = channel_for(string_view(msg, 8, 32)).lock()) {
        return channel->receive(msg, src);
    }
}

} // comm namespace
} // uia namespace
