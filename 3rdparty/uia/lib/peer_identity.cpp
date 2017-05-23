//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/peer_identity.h"
#include "arsenal/settings_provider.h"
#include <boost/log/trivial.hpp>

using namespace std;
using namespace sodiumpp;
using arsenal::byte_array;

namespace uia {

//=================================================================================================
// identity
//=================================================================================================

peer_identity::peer_identity(string const& id)
    : id_(id)
{
}

peer_identity::peer_identity(string const& id, string const& key)
    : id_(id)
{
    if (!set_key(key)) {
        throw bad_key();
    }
}

void
peer_identity::clear_key()
{
    private_key_.clear();
}

bool
peer_identity::set_key(string const& key)
{
    clear_key();

    private_key_ = key;

    // Verify that the supplied key actually matches the ID we have.
    // *** This is a crucial step for security! ***
    string test = "this is a key test";
    // @todo Verify by encrypting with public key and then decrypting with secret key
    // if (key_id != id_)
    // {
    //     clear_key();
    //     logger::warning() << "Attempt to set mismatching identity key!";
    //     return false;
    // }

    return true;
}

peer_identity
peer_identity::generate()
{
    box_secret_key k;
    return peer_identity(k.pk.get().to_binary(), k.get().to_binary());
}

string
peer_identity::public_key() const
{
    return id_;
}

box_secret_key
peer_identity::secret_key() const
{
    return box_secret_key(
        box_public_key(encoded_bytes(id_, encoding::binary)),
        encoded_bytes(private_key_, encoding::binary));
}

//=================================================================================================
// identity_host_state
//=================================================================================================

peer_identity
identity_host_state::host_identity()
{
    if (!host_identity_.has_private_key()) {
        host_identity_ = peer_identity::generate();
    }
    return host_identity_;
}

void
identity_host_state::set_host_identity(peer_identity const& ident)
{
    if (!ident.has_private_key()) {
        BOOST_LOG_TRIVIAL(warning) << "Using a host identity with no private key!";
    }
    host_identity_ = ident;
}

void
identity_host_state::init_identity(arsenal::settings_provider* settings)
{
    if (host_identity_.has_private_key())
        return; // Already initialized.

    if (!settings) {
        host_identity_ = peer_identity::generate(); // No persistence available.
        return;
    }

    // Find and decode the host's existing key, if any.
    byte_array id  = settings->get_byte_array("id");
    byte_array key = settings->get_byte_array("key");

    if (!id.is_empty() and !key.is_empty()) {
        host_identity_.set_id(id.as_string());
        if (host_identity_.set_key(key.as_string()) and host_identity_.has_private_key())
            return; // Success
    }

    BOOST_LOG_TRIVIAL(warning) << "Invalid host identity in settings: generating new identity";

    // Generate a new key pair
    host_identity_ = peer_identity::generate();

    // Save it in our host settings
    settings->set("id", host_identity_.public_key());
    settings->set("key", host_identity_.secret_key().get().to_binary());
    settings->sync();
}

} // uia namespace
