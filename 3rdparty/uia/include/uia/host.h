//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "uia/peer_identity.h"
#include "uia/timer.h"
#include "uia/comm/socket_protocol.h"
#include "uia/negotiation/kex_host_state.h"
#include "uia/comm/socket_host_state.h"
#include "uia/channels/channel_host_state.h"
#include "uia/asio_host_state.h"

namespace uia {

class host : public std::enable_shared_from_this<host>,
             public comm::socket_host_state,
             public negotiation::kex_host_state,
             public identity_host_state,
             public timer_host_state,
             public comm::channel_host_state,
             protected virtual asio_host_state
{
protected:
    struct private_tag
    {
    };

public:
    // Hide the constructor.
    explicit host(private_tag) {}
    ~host() { logger::debug() << "~host " << this; }

    inline host_ptr get_host() override { return shared_from_this(); }

    /**
     * @name Factory functions.
     * Use those to create host instance.
     */
    /**@{*/
    /**
     * Create a "bare-bones" host state object with no sockets or identity.
     * Client must establish a host identity via set_host_identity()
     * and activate one or more network sockets before using sss.
     */
    static host_ptr create();
    /**
     * Create an easy-to-use default Host object. Uses the provided setting_provider
     * registry to locate, or create if necessary, a persistent host identity,
     * as described for identity_host_state::init_identity().
     * Also creates and binds to at least one UDP socket, using a UDP port number specified
     * in the settings_provider, or defaulting to @a default_port if not.
     * If the desired UDP port cannot be bound, just picks an arbitrary UDP port instead
     * and updates settings with this new value.
     */
    static host_ptr create(settings_provider* settings,
                           uint16_t default_port = uia::comm::DEFAULT_PORT);
    // Overload with shared pointer to settings.
    static inline host_ptr create(std::shared_ptr<settings_provider> settings,
                                  uint16_t default_port = uia::comm::DEFAULT_PORT)
    {
        return create(settings.get(), default_port);
    }
    /**@}*/
};

} // uia namespace
