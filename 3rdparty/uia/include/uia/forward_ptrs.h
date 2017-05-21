//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <memory>

namespace uia {

class host;
class socket_channel;

using host_ptr  = std::shared_ptr<host>;
using host_wptr = std::weak_ptr<host>;
using host_uptr = std::unique_ptr<host>;

using socket_channel_ptr  = std::shared_ptr<socket_channel>;
using socket_channel_wptr = std::weak_ptr<socket_channel>;
using socket_channel_uptr = std::unique_ptr<socket_channel>;

namespace comm {

class socket;
class packet_receiver;
class message_receiver;

using socket_ptr  = std::shared_ptr<socket>;
using socket_wptr = std::weak_ptr<socket>;
using socket_uptr = std::unique_ptr<socket>;

using packet_receiver_ptr  = std::shared_ptr<packet_receiver>;
using packet_receiver_wptr = std::weak_ptr<packet_receiver>;
using packet_receiver_uptr = std::unique_ptr<packet_receiver>;

using message_receiver_ptr  = std::shared_ptr<message_receiver>;
using message_receiver_wptr = std::weak_ptr<message_receiver>;
using message_receiver_uptr = std::unique_ptr<message_receiver>;

} // comm namespace

namespace negotiation {

class initiator;
class responder;

using initiator_ptr  = std::shared_ptr<initiator>;
using initiator_wptr = std::weak_ptr<initiator>;

using responder_ptr  = std::shared_ptr<responder>;
using responder_wptr = std::weak_ptr<responder>;

} // negotiation namespace

namespace simulation {

class sim_host;
class sim_connection;
class simulator;

using sim_host_ptr  = std::shared_ptr<sim_host>;
using sim_host_wptr = std::weak_ptr<sim_host>;
using sim_host_uptr = std::unique_ptr<sim_host>;

using sim_connection_ptr  = std::shared_ptr<sim_connection>;
using sim_connection_wptr = std::weak_ptr<sim_connection>;
using sim_connection_uptr = std::unique_ptr<sim_connection>;

using simulator_ptr  = std::shared_ptr<simulator>;
using simulator_wptr = std::weak_ptr<simulator>;
using simulator_uptr = std::unique_ptr<simulator>;

} // simulation namespace
} // uia namespace
