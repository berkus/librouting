//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/asio_host_state.h"
#include <boost/thread.hpp>
#include <boost/bind.hpp>

using namespace boost;

namespace uia {

void asio_host_state::run_io_service()
{
    thread_group group;
    for (unsigned i = 0; i < thread::hardware_concurrency(); ++i) {
        group.create_thread(boost::bind(&asio::io_service::run, ref(io_service_)));
    }
    group.join_all();
}

} // uia namespace
