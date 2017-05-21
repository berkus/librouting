//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#define BOOST_TEST_MODULE Test_negotiation
#include <boost/test/unit_test.hpp>
#include "simulator_fixture.h"
#include "uia/peer.h"

using namespace std;
using namespace uia;
using namespace uia::simulation;

BOOST_FIXTURE_TEST_CASE(negotiate_channel, simulator_fixture)
{
    uia::internal::peer client(client_host, server_host_eid),
                        server(server_host, client_host_eid);

    client.add_location_hint(server_host_address);
    client.connect_channel();
    simulator->run();

    logger::debug() << "<<< shutdown from this point on";
}
