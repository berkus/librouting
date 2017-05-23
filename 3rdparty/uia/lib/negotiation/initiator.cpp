//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "uia/negotiation/initiator.h"
#include "uia/negotiation/responder.h"
#include "arsenal/byte_array_wrap.h"
#include "arsenal/algorithm.h"
#include "arsenal/subrange.h"
#include "arsenal/flurry.h"
#include "arsenal/proquint.h"
#include "uia/host.h"
#include "uia/channels/socket_channel.h"
#include "uia/packet_format.h"
#include <boost/log/trivial.hpp>

using namespace std;
using namespace sodiumpp;

namespace {

template <typename T>
bool
socket_send(uia::comm::socket_endpoint const& target, T const& msg)
{
    static std::mutex mtx;
    std::lock_guard<std::mutex> lock(mtx);
    char stack[1280] = {0}; // @todo Use a send packet pool
    boost::asio::mutable_buffer buf(stack, 1280);
    auto end = arsenal::fusionary::write(buf, msg);
    return target.send(boost::asio::buffer_cast<const char*>(buf),
                       boost::asio::buffer_size(buf) - boost::asio::buffer_size(end));
    // @fixme send() buf might outlive the scope of this func
}

} // anonymous namespace

namespace uia::negotiation {

//=================================================================================================
// initiator
//=================================================================================================

initiator::initiator(host_ptr host, peer_identity const& target_peer, comm::socket_endpoint target)
    : host_(host)
    , target_(target)
    , remote_id_(target_peer)
    , retransmit_timer_(host.get())
    , minute_timer_(host.get())
{
    BOOST_LOG_TRIVIAL(debug) << "Creating kex initiator " << this;

    assert(target_ != uia::comm::endpoint());
    retransmit_timer_.on_timeout.connect([this](bool fail) { retransmit(fail); });
    minute_timer_.on_timeout.connect([this](bool fail) { cookie_expired(); });

    BOOST_LOG_TRIVIAL(debug) << "Long term responder pk "
        << arsenal::encode::to_proquint(remote_id_.public_key());
}

initiator::~initiator()
{
    BOOST_LOG_TRIVIAL(debug) << "Destroying initiator " << this;
    cancel();
}

void
initiator::exchange_keys()
{
    BOOST_LOG_TRIVIAL(debug) << "Initiating key exchange connection to peer " << target_ << "/"
                    << remote_id_;
    host_->register_initiator(target_, shared_from_this());
    send_hello();
}

void
initiator::retransmit(bool fail)
{
    if (fail) {
        BOOST_LOG_TRIVIAL(debug) << "Key exchange failed";
        state_ = state::done;
        retransmit_timer_.stop();
        minute_timer_.stop();
        return on_completed(shared_from_this(), nullptr);
    }

    BOOST_LOG_TRIVIAL(debug) << "Time to retransmit the key exchange packet.";

    // If we're gonna resend the init packet, make sure we are registered as a receiver for
    // response packets.
    host_->register_initiator(target_, shared_from_this());

    if (state_ == state::hello) {
        send_hello();
    } else if (state_ == state::initiate) {
        send_initiate(minute_cookie_, "");
        // @todo Retry initiate packets only during minute key validity period, then
        // fallback to Hello packet again...
    }
    retransmit_timer_.restart();
}

/**
 * Cookie has expired, so we should retry from the very beginning.
 */
void
initiator::cookie_expired()
{
    if (state_ == state::initiate) {
        return;
    }
}

void
initiator::done()
{
    assert(channel_);

    bool send_signal = (state_ != state::done);
    BOOST_LOG_TRIVIAL(debug) << "Key exchange completed with " << target_
                    << (send_signal ? " (signaling upper layer)" : "");
    state_ = state::done;
    cancel();
    if (send_signal) {
        on_completed(shared_from_this(), channel_);
    }
}

void
initiator::cancel()
{
    BOOST_LOG_TRIVIAL(debug) << "Stop initiating to " << target_;
    retransmit_timer_.stop();
    minute_timer_.stop();
    host_->unregister_initiator(target_);
}

void
initiator::send_hello()
{
    BOOST_LOG_TRIVIAL(debug) << "Send HELLO to " << target_;

    boxer<nonce64> seal(remote_id_.public_key(), short_term_secret_key, HELLO_NONCE_PREFIX);
    auto box_contents = host_->host_identity().secret_key().pk.get() + string(32, '\0');

    uia::packets::hello_packet_header pkt;
    pkt.initiator_shortterm_public_key = as_array<32>(short_term_secret_key.pk.get().to_binary());
    pkt.box                            = as_array<80>(seal.box(box_contents));
    pkt.nonce                          = as_array<8>(seal.nonce_sequential());

    socket_send(target_, pkt);
    retransmit_timer_.start();
    state_ = state::hello;
}

// This is called by kex_responder's packet handling machinery.
void
initiator::got_cookie(boost::asio::const_buffer buf, uia::comm::socket_endpoint const& src)
{
    BOOST_LOG_TRIVIAL(debug) << "initiator::got_cookie from endpoint " << src;
    if (src != target_)
        return; // not our cookie!

    uia::packets::cookie_packet_header cookie;
    arsenal::fusionary::read(cookie, buf);

    // open cookie box
    string nonce = COOKIE_NONCE_PREFIX + as_string(cookie.nonce);

    unboxer<recv_nonce> unseal(remote_id_.public_key(), short_term_secret_key, nonce);
    string open = unseal.unbox(as_string(cookie.box));

    server_short_term_public_key = arsenal::subrange(open, 0, 32);
    minute_cookie_               = arsenal::subrange(open, 32, 96);

    // remember cookie for 1 minute
    minute_timer_.start();

    // optimistically spawn a channel here and let client prepare some data
    // to send in the initiate packet
    create_channel(
        short_term_secret_key, server_short_term_public_key, remote_id_.public_key(), src);
    // channel should be created in "setting up" state to indicate that
    // no ACKs have been received from the other side yet.

    // @todo: Resource management gets tricky, if we get no response to our initiate, we need
    // to destroy the channel, return all send-but-not-acked data to client and start over.

    send_initiate(minute_cookie_, "");
}

void
initiator::create_channel(sodiumpp::secret_key local_short,
                          sodiumpp::public_key remote_short,
                          sodiumpp::public_key remote_long,
                          uia::comm::socket_endpoint const& responder_ep)
{
    BOOST_LOG_TRIVIAL(debug) << "initiator::create_channel optimistically for " << responder_ep;
    channel_ = host_->channel_responder()->create_channel(
        local_short, remote_short, remote_long, responder_ep);

    channel_->on_ready_transmit(); // up to 1 packet can be sent now
    // but this is useless, because nobody has connected to the channel yet....
    // so initiate packet is always empty for now...
}

void
initiator::send_initiate(std::string cookie, std::string payload)
{
    // Create vouch subpacket
    boxer<random_nonce<8>> vouchSeal(
        remote_id_.public_key(), host_->host_identity().secret_key(), VOUCH_NONCE_PREFIX);
    string vouch = vouchSeal.box(short_term_secret_key.pk.get());
    assert(vouch.size() == 48);

    // Assemble initiate packet
    uia::packets::initiate_packet_header pkt;
    pkt.initiator_shortterm_public_key = as_array<32>(short_term_secret_key.pk.get());
    pkt.responder_cookie.nonce         = as_array<16>(arsenal::subrange(cookie, 0, 16));
    pkt.responder_cookie.box           = as_array<80>(arsenal::subrange(cookie, 16));

    auto box_contents = host_->host_identity().secret_key().pk.get() + vouchSeal.nonce_sequential()
                        + vouch + payload;
    boxer<nonce64> seal(server_short_term_public_key, short_term_secret_key, INITIATE_NONCE_PREFIX);
    pkt.box = seal.box(box_contents);
    // @todo Round payload size to next or second next multiple of 16..
    pkt.nonce = as_array<8>(seal.nonce_sequential());

    socket_send(target_, pkt);
    retransmit_timer_.start();
    state_ = state::initiate;
}

} // uia::negotiation namespace
