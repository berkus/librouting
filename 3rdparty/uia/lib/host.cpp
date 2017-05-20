//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/host.h"

using namespace std;

namespace uia {

host_ptr
host::create()
{
    shared_ptr<host> host(make_shared<host>(private_tag()));
    return host;
}

host_ptr
host::create(arsenal::settings_provider* settings, uint16_t default_port)
{
    shared_ptr<host> host(make_shared<host>(private_tag()));
    host->init_socket(settings, default_port);
    host->init_identity(settings);
    return host;
}

} // uia namespace
