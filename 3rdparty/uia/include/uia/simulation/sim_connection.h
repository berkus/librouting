//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include "uia/comm/socket_endpoint.h"
#include "uia/timer.h"

namespace uia {
namespace simulation {

class simulator;
class sim_host;

class sim_connection : public std::enable_shared_from_this<sim_connection>
{
public:
    using ptr = std::shared_ptr<sim_connection>;
    using weak_ptr = std::weak_ptr<sim_connection>;
public:
    struct params {
        int rate;  ///< Bandwidth in bytes per second.
        async::timer::duration_type delay; ///< Connection delay.
        async::timer::duration_type queue; ///< Router queue delay.
        float loss; ///< Loss rate from 0.0 (100% reliable) to 1.0 (not delivering anything).

        std::string to_string() const;
    };

    enum preset {
        dsl_15,      ///< 1.5Mbps/384Kbps DSL link
        cable_5,     ///< 5Mbps cable modem link
        sat_10,      ///< 10Mbps satellite link with 500ms delay
        eth_10,      ///< 10Mbps Ethernet link
        eth_100,     ///< 100Mbps Ethernet link
        eth_1000,    ///< 1000Mbps Ethernet link
        wifi_54,     ///< 802.11g-2003 WiFi link
        wifi_600,    ///< 802.11n hi-speed WiFi link
    };

    sim_connection(preset p = eth_100);
    ~sim_connection();

    void connect(std::shared_ptr<sim_host> downlink, uia::comm::endpoint downlink_address,
                 std::shared_ptr<sim_host> uplink, uia::comm::endpoint uplink_address);
    void disconnect();

    void set_preset(preset p);
    inline void set_link_params(params const& downlink, params const& uplink) {
        downlink_params_ = downlink;
        uplink_params_ = uplink;
    }
    inline void set_link_params(params const& updownlink) {
        set_link_params(updownlink, updownlink);
    }

    std::shared_ptr<sim_host> uplink_for(std::shared_ptr<sim_host> downlink) const;
    uia::comm::endpoint address_for(std::shared_ptr<sim_host> link) const;

    params const& params_for(std::shared_ptr<sim_host> host) const;
    boost::posix_time::ptime& arrival_time_for(std::shared_ptr<sim_host> host);

private:
    std::shared_ptr<sim_host> uplink_, downlink_;
    uia::comm::endpoint uplink_address_, downlink_address_;
    params uplink_params_, downlink_params_;
    // Current arrival times for packets in uplink and downlink directions.
    boost::posix_time::ptime uplink_arrival_time_, downlink_arrival_time_;
};

} // simulation namespace
} // sss namespace
