//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2015, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/negotiation/kex_host_state.h"
#include "uia/negotiation/responder.h"
#include "uia/negotiation/constants.h"
#include "arsenal/logging.h"

namespace uia::negotiation {

void
kex_host_state::instantiate_responder()
{
    if (!responder_) {
        responder_ = std::make_shared<responder>(get_host());
        responder_->bind(magic::hello_packet::value);
        responder_->bind(magic::cookie_packet::value);
        responder_->bind(magic::initiate_packet::value);
    }
    assert(responder_);
}

initiator_ptr
kex_host_state::get_initiator(uia::comm::endpoint ep)
{
    std::lock_guard<std::mutex> lock(initiators_mutex_);
    auto it = initiators_.find(ep);
    if (it == initiators_.end()) {
        return nullptr;
    }
    return it->second;
}

void
kex_host_state::register_initiator(uia::comm::endpoint ep, initiator_ptr ki)
{
    logger::debug() << "Adding initiator " << ki << " for endpoint " << ep;
    std::lock_guard<std::mutex> lock(initiators_mutex_);
    initiators_.insert(make_pair(ep, ki));
}

void
kex_host_state::unregister_initiator(uia::comm::endpoint ep)
{
    logger::debug() << "Removing initiator for endpoint " << ep;
    std::lock_guard<std::mutex> lock(initiators_mutex_);
    initiators_.erase(ep);
}

} // uia::negotiation namespace
