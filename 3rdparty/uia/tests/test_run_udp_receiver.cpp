//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/comm/udp_socket.h"
#include "uia/host.h"

using namespace std;
using namespace uia;
using namespace uia::comm;
using namespace boost::asio;

int
main()
{
    try {
        host_ptr host(host::create());
        endpoint local_ep(ip::udp::v4(), DEFAULT_PORT);
        udp_socket l(host);
        l.bind(local_ep);
        l.send(local_ep, "\0SSSohai!", 10);
        // host->run_io_service();
    } catch (exception& e) {
        cerr << e.what() << endl;
    }
}
