//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#define BOOST_TEST_MODULE Test_endpoint_set
#include <boost/test/unit_test.hpp>

#include "uia/comm/endpoint_set.h"

using namespace std;
using namespace uia;
using namespace uia::comm;

struct EpsFixture
{
    endpoint_set eps{
        endpoint(boost::asio::ip::address::from_string("127.0.0.1"), 1024),
        endpoint(boost::asio::ip::address::from_string("192.168.0.1"), 1024),
        endpoint(boost::asio::ip::address::from_string("192.168.10.255"), 1024),
        endpoint(boost::asio::ip::address::from_string("10.0.0.1"), 1024),
        endpoint(boost::asio::ip::address::from_string("10.10.10.1"), 1024),
        endpoint(boost::asio::ip::address::from_string("8.8.8.8"), 1024),
        endpoint(boost::asio::ip::address::from_string("0.0.0.1"), 1024),
        endpoint(boost::asio::ip::address::from_string("::fff1"), 1024),
        endpoint(boost::asio::ip::address::from_string("::1"), 1024),
        // own endpoint address
        endpoint(boost::asio::ip::address::from_string("85.253.73.240"), 1024),
        // presumable gateway addresses
        endpoint(boost::asio::ip::address::from_string("85.253.73.1"), 1024),
        endpoint(boost::asio::ip::address::from_string("85.253.73.2"), 1024),
        endpoint(boost::asio::ip::address::from_string("85.253.73.255"), 1024),
        endpoint(boost::asio::ip::address::from_string("85.253.73.254"), 1024),
    };
};

BOOST_FIXTURE_TEST_CASE(ipv4_simple_affinity, EpsFixture)
{
    endpoint my_ep(boost::asio::ip::address::from_string("85.253.73.240"), 1024);

    cout << "Endpoints near " << my_ep << endl;
    for (auto x : eps.affinity_sorted_to(my_ep)) {
        cout << x << endl;
    }
}

BOOST_FIXTURE_TEST_CASE(ipv6_simple_affinity, EpsFixture)
{
    endpoint my_ep(boost::asio::ip::address::from_string("::1"), 1024);

    cout << "Endpoints near " << my_ep << endl;
    for (auto x : eps.affinity_sorted_to(my_ep)) {
        cout << x << endl;
    }
}

BOOST_AUTO_TEST_CASE(nat_affinity)
{
    // Advanced cases - give more affinity to nearby NAT gates
}
