//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/negotiation/responder.h"
#include "uia/negotiation/initiator.h"
#include "uia/host.h"
#include "uia/channels/socket_channel.h"
#include "uia/negotiation/crypto_types.h"
#include "uia/negotiation/constants.h"
#include "uia/packet_format.h"
#include "uia/basic_framing_types.h"
#include "arsenal/byte_array_wrap.h"
#include "arsenal/fusionary.hpp"
#include "arsenal/algorithm.h"
#include "arsenal/subrange.h"
#include <boost/make_unique.hpp>
#include <boost/log/trivial.hpp>

using namespace std;
using namespace sodiumpp;

//=================================================================================================
// Supplemental functions.
//=================================================================================================

namespace {

void
warning(string message)
{
    BOOST_LOG_TRIVIAL(warning) << "Key exchange - " << message;
}

template <typename T>
bool
socket_send(uia::comm::socket_endpoint const& target, T const& msg)
{
    static std::mutex mtx;
    std::lock_guard<std::mutex> guard(mtx);
    char stack[1280] = {0}; // @todo Use a send packet pool
    boost::asio::mutable_buffer buf(stack, 1280);
    auto end = arsenal::fusionary::write(buf, msg);
    return target.send(boost::asio::buffer_cast<const char*>(buf),
                       boost::asio::buffer_size(buf) - boost::asio::buffer_size(end));
}

} // anonymous namespace

namespace uia {

void
socket_channel::send_message(string payload)
{
    BOOST_LOG_TRIVIAL(debug) << "Channel sending MESSAGE to " << remote_ep_;
    uia::packets::message_packet_header packet;

    boxer<random_nonce<16>> seal(
        remote_key_,
        local_key_,
        encoded_bytes(MESSAGE_NONCE_PREFIX, encoding::binary));
    auto box = seal.box(payload);

    packet.shortterm_public_key = as_array<32>(local_key_.pk.get().to_binary());
    packet.box = box.to_binary();
    packet.nonce = as_array<8>(seal.get_nonce().get_sequential().to_binary());

    socket_send(comm::socket_endpoint(socket_, remote_ep_), packet);
}

namespace negotiation {

//=================================================================================================
// responder
//=================================================================================================

responder::responder(host_ptr host)
    : packet_receiver(host)
    , host_(host)
    , minute_key_rotation_(host.get())
{
}

bool
responder::is_initiator_acceptable(uia::comm::socket_endpoint const& initiator_ep,
                                   uia::peer_identity const& initiator_eid,
                                   arsenal::byte_array const& user_data)
{
    return true;
}

socket_channel_uptr
responder::create_channel(sodiumpp::box_secret_key local_short,
                          sodiumpp::box_public_key remote_short,
                          sodiumpp::box_public_key remote_long,
                          uia::comm::socket_endpoint const& initiator_ep)
{
    auto ch = boost::make_unique<socket_channel>(local_short, remote_short, initiator_ep);
    ch->start();
    return ch;
}

void
responder::receive(boost::asio::const_buffer msg, uia::comm::socket_endpoint const& src)
{
    BOOST_LOG_TRIVIAL(debug) << "responder::receive " << dec << boost::asio::buffer_size(msg)
                    << " bytes from " << src;

    auto magic = *boost::asio::buffer_cast<const comm::packet_magic_t*>(msg);
    switch (magic) {
        case uia::magic::hello_packet::value:
            return got_hello(msg, src);
        case uia::magic::cookie_packet::value: {
            auto initiator = host_->get_initiator(src);
            BOOST_LOG_TRIVIAL(debug) << "Found initiator " << initiator;
            return initiator->got_cookie(msg, src);
        }
        case uia::magic::initiate_packet::value:
            return got_initiate(msg, src);
        // case magic::r0_packet::value:
            // a responder's ping packet for hole punching.
            // return got_probe(src);
    }

    // If there was no recognized packet, just ignore it.
}

void
responder::got_hello(boost::asio::const_buffer msg, uia::comm::socket_endpoint const& src)
{
    BOOST_LOG_TRIVIAL(debug) << "Responder got hello packet from " << src;
    uia::packets::hello_packet_header hello;
    arsenal::fusionary::read(hello, msg);

    auto clientKey = encoded_bytes(as_string(hello.initiator_shortterm_public_key), encoding::binary);

    unboxer<nonce128> unseal(
        box_public_key(clientKey),
        host_->host_identity().secret_key(),
        encoded_bytes("", encoding::binary));
    auto open = unseal.unbox(
        encoded_bytes(as_string(hello.box), encoding::binary),
        encoded_bytes(HELLO_NONCE_PREFIX + as_string(hello.nonce), encoding::binary));

    // Open box contains client's long-term public key which we should check against a blacklist

    // Send cookie packet if we're willing to accept connection.
    // We never resend the cookie (spec 3.1.1), initiator will repeat hello if packets get lost.
    send_cookie(clientKey.to_binary(), src);
}

void
responder::send_cookie(string clientKey, uia::comm::socket_endpoint const& src)
{
    BOOST_LOG_TRIVIAL(debug) << "Responder sending cookie to " << src;
    uia::packets::cookie_packet_header packet;
    uia::packets::responder_cookie cookie;
    box_secret_key sessionKey; // Generate short-term server key

    // minute-key secretbox nonce
    random_nonce<8> minuteKeyNonce(encoded_bytes(MINUTEKEY_NONCE_PREFIX, encoding::binary));
    // Client short-term public key + Server short-term secret key
    cookie.box = as_array<80>(
        crypto_secretbox(clientKey + sessionKey.get().to_binary(),
            minuteKeyNonce.get().to_binary(),
            minute_key.get().to_binary()));

    // Compressed cookie nonce
    cookie.nonce = as_array<16>(minuteKeyNonce.get_sequential().to_binary());

    boxer<random_nonce<8>> seal(
        encoded_bytes(clientKey, encoding::binary),
        host_->host_identity().secret_key(),
        encoded_bytes(COOKIE_NONCE_PREFIX, encoding::binary));

    // Server short-term public key + cookie
    // Box the cookies
    string box = seal.box(sessionKey.pk.get().to_binary() + as_string(cookie)).to_binary();
    assert(box.size() == 96 + 32 + 16);

    packet.nonce = as_array<16>(seal.get_nonce().get_sequential().to_binary());
    packet.box   = as_array<144>(box);

    socket_send(src, packet);
}

void
responder::got_initiate(boost::asio::const_buffer buf, uia::comm::socket_endpoint const& src)
{
    BOOST_LOG_TRIVIAL(debug) << "Responder got initiate packet from " << src;
    uia::packets::initiate_packet_header init;
    buf = arsenal::fusionary::read(init, buf);

    // Try to open the cookie
    string nonce = MINUTEKEY_NONCE_PREFIX + as_string(init.responder_cookie.nonce);

    string cookie = crypto_secretbox_open(
        as_string(init.responder_cookie.box),
        nonce,
        minute_key.get().to_binary());

    // Check that cookie and client match
    if (as_string(init.initiator_shortterm_public_key) != string(arsenal::subrange(cookie, 0, 32)))
        return warning("cookie and client mismatch");

    // Extract server short-term key
    string secret_k = arsenal::subrange(cookie, 32, 32);
    string public_k = crypto_scalarmult_base(secret_k);
    short_term_key = box_secret_key(
        encoded_bytes(public_k, encoding::binary),
        encoded_bytes(secret_k, encoding::binary));

    // Open the Initiate box using both short-term keys
    string initiateNonce = INITIATE_NONCE_PREFIX + as_string(init.nonce);

    unboxer<nonce128> unseal(
        encoded_bytes(as_string(init.initiator_shortterm_public_key), encoding::binary),
        short_term_key,
        encoded_bytes(initiateNonce, encoding::binary));
    string msg = unseal.unbox(encoded_bytes(as_string(init.box), encoding::binary));

    // Extract client long-term public key and check the vouch subpacket.
    string client_long_term_key = arsenal::subrange(msg, 0, 32);

    string vouchNonce = VOUCH_NONCE_PREFIX + string(arsenal::subrange(msg, 32, 16));

    unboxer<nonce128> vouchUnseal(
        encoded_bytes(client_long_term_key, encoding::binary),
        host_->host_identity().secret_key(),
        encoded_bytes(vouchNonce, encoding::binary));
    auto vouch = vouchUnseal.unbox(encoded_bytes(arsenal::subrange(msg, 48, 48), encoding::binary));

    if (vouch != as_string(init.initiator_shortterm_public_key))
        return warning("vouch subpacket invalid");

    client_short_term_key = vouch;

    BOOST_LOG_TRIVIAL(debug) << "Responder VALIDATED initiate packet from " << src;

    // Channel needs two pairs of short-term keys and remote endpoint to operate
    channel_ = create_channel(
        short_term_key,
        encoded_bytes(client_short_term_key, encoding::binary),
        encoded_bytes(client_long_term_key, encoding::binary),
        src);

    // All is good, what's in the payload?
    // @todo Pass payload to the channel.
    // chan->receive(buf, src);

    // string payload = subrange(msg, 96);
    // hexdump(payload);

    // Send back message as an ACK so that initiator stops trying
    channel_->send_message("");

    // Indicate KEX is successful
    on_completed();
}

void
responder::got_probe(boost::asio::const_buffer msg, comm::socket_endpoint const& src)
{
    // Trigger a retransmission of the dh_init1 packet
    // for each outstanding initiation attempt to the given target.
    BOOST_LOG_TRIVIAL(debug) << "Responder got probe packet from " << src;

    // @todo This ruins the init/response chain for the DH exchange
    // Peers are left in a perpetual loop of reinstating almost always broken peer channel.
    // To fix this, we might not send R0 packets from the peer being contacted if it detects that
    // the same address is already attempting to establish a session.
    // This is not entirely robust though.
    // The other thing might be replay protection, refuse continuing the contact after dh_init1 if
    // there's a duplicate request coming in (that's how it should work I believe).
    // dh.cpp has r2_cache_ of r2 replay protection data.

    // auto pairs = get_host()->get_initiators(src);
    // while (pairs.first != pairs.second)
    // {
    //     auto initiator = (*pairs.first).second;
    //     ++pairs.first;
    //     if (!initiator or initiator->state_ != key_initiator::state::init1)
    //         continue;

    //     initiator->send_dh_init1();
    // }
}

void
responder::send_probe(comm::endpoint dest)
{
    BOOST_LOG_TRIVIAL(debug) << "Send probe0 to " << dest;
    // for (auto s : get_host()->active_sockets()) {
    //     uia::comm::socket_endpoint ep(s, dest);
    //     send_r0(magic(), ep);
    // }
}

} // negotiation namespace
} // uia namespace
