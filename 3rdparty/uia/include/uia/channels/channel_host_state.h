//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "arsenal/algorithm.h"
#include "uia/forward_ptrs.h"

namespace uia {
namespace comm {

using packet_magic_t = uint64_t;

class channel_host_state
{
    /**
     * Lookup table of all registered packet_receivers for this host, keyed on their magic.
     */
    std::unordered_map<packet_magic_t, uia::comm::packet_receiver_wptr> receivers_;

    message_receiver_ptr receiver_;

    virtual host_ptr get_host() = 0;

public:
    void register_receiver();

    // Interface to bind and lookup receivers based on packet magic value.
    // bind_receiver(magic::hello, kex_responder)
    // bind_receiver(magic::cookie, kex_initiator)
    // bind_receiver(magic::initiate, kex_responder)
    // bind_receiver(magic::message, message_receiver)

    /*@{*/
    /*@name receiver_host_interface implementation */
    /**
     * Create a receiver and bind it to control channel magic.
     */
    virtual void bind_receiver(packet_magic_t magic, packet_receiver_wptr receiver)
    {
        // @todo: Will NOT replace existing element.
        receivers_.insert(std::make_pair(magic, receiver));
    }

    virtual void unbind_receiver(packet_magic_t magic) { receivers_.erase(magic); }

    virtual bool has_receiver_for(packet_magic_t magic) { return contains(receivers_, magic); }

    /**
     * Find and return a receiver for given control channel magic value.
     */
    virtual packet_receiver_wptr receiver_for(packet_magic_t magic);
    /*@}*/
};

} // comm namespace
} // uia namespace
