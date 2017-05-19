//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <iostream>
#include "arsenal/logging.h"
#include "uia/simulation/simulator.h"
#include "uia/simulation/sim_host.h"
#include "uia/simulation/sim_socket.h"
#include "uia/simulation/sim_connection.h"
#include "uia/forward_ptrs.h"

struct simulator_fixture
{
    uia::simulation::simulator_ptr simulator;
    uia::simulation::sim_connection_ptr server_client_connection;

    uia::simulation::sim_host_ptr server_host;
    uia::peer_identity server_host_eid;
    uia::comm::endpoint server_host_address;
    uia::comm::socket_ptr server_socket;

    uia::simulation::sim_host_ptr client_host;
    uia::peer_identity client_host_eid;
    uia::comm::endpoint client_host_address;
    uia::comm::socket_ptr client_socket;

    simulator_fixture()
    {
        simulator = std::make_shared<uia::simulation::simulator>();
        BOOST_CHECK(simulator != nullptr);

        setup_test_server();
        setup_test_client();
        setup_test_connection();
    }

    ~simulator_fixture()
    {
        server_client_connection.reset();
        client_socket.reset();
        client_host.reset();
        server_socket.reset();
        server_host.reset();
        simulator.reset();
        logger::debug() << "<<< host use counts after reset " << std::dec << client_host.use_count()
                        << " and " << server_host.use_count();
    }

    void setup_test_server()
    {
        server_host = uia::simulation::sim_host::create(simulator);
        BOOST_CHECK(server_host != nullptr);
        server_host_eid = server_host->host_identity().id();
        server_host_address =
            uia::comm::endpoint(boost::asio::ip::address_v4::from_string("10.0.0.1"),
                                uia::comm::DEFAULT_PORT);

        server_socket = server_host->create_socket();
        BOOST_CHECK(server_socket != nullptr);
        server_socket->bind(server_host_address);
        BOOST_CHECK(server_socket->is_active());
    }

    void setup_test_client()
    {
        client_host = uia::simulation::sim_host::create(simulator);
        BOOST_CHECK(client_host != nullptr);
        client_host_eid = client_host->host_identity().id();
        client_host_address =
            uia::comm::endpoint(boost::asio::ip::address_v4::from_string("10.0.0.2"),
                                uia::comm::DEFAULT_PORT);

        client_socket = client_host->create_socket();
        BOOST_CHECK(client_socket != nullptr);
        client_socket->bind(client_host_address);
        BOOST_CHECK(client_socket->is_active());
    }

    void setup_test_connection()
    {
        server_client_connection = std::make_shared<uia::simulation::sim_connection>();
        BOOST_CHECK(server_client_connection != nullptr);
        server_client_connection->connect(
            server_host, server_host_address, client_host, client_host_address);
    }
};
