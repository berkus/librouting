//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//

//
// Part of Metta OS. Check http://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "uia/comm/socket.h"
#include "uia/timer.h"
#include "arsenal/byte_array.h"
#include <boost/date_time/posix_time/posix_time_types.hpp>

namespace uia::simulation {

class simulator;
class sim_host;
class sim_connection;

class sim_packet : public std::enable_shared_from_this<sim_packet>
{
    boost::posix_time::ptime arrival_time_;
    std::shared_ptr<simulator> simulator_;
    uia::comm::endpoint from_, to_;
    std::shared_ptr<sim_host> target_host_;
    std::shared_ptr<sim_connection> pipe_;
    arsenal::byte_array data_;
    async::timer timer_;

    void arrive();

public:
    sim_packet(std::shared_ptr<sim_host> source_host, uia::comm::endpoint const& src,
        std::shared_ptr<sim_connection> pipe, uia::comm::endpoint const& dst,
        arsenal::byte_array data);
    ~sim_packet();

    void send();

    boost::posix_time::ptime arrival_time() const { return arrival_time_; }
};

} // uia::simulation namespace
