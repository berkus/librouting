//
// Part of Metta OS. Check http://atta-metta.net for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@atta-metta.net>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include <regex>
#include "arsenal/logging.h"
#include "uia/peer_identity.h"
#include "uia/comm/socket.h"
#include "uia/comm/udp_socket.h"
#include "routing/private/regserver_client.h" // For some shared constants
#include "sss/host.h"
#include "regserver.h"

using namespace uia::routing::internal;
using namespace std;
using namespace sss;
namespace asio = boost::asio;

constexpr int MAX_RESULTS = 100; // Maximum number of search results

namespace uia {
namespace routing {

//=================================================================================================
// registration_server implementation
//=================================================================================================

registration_server::registration_server(std::shared_ptr<sss::host> host)
    : host_(host)
    , sock(io_service_)
    , sock6(io_service_)
{
    asio::ip::udp::endpoint ep(asio::ip::address_v4::any(), REGSERVER_DEFAULT_PORT);
    asio::ip::udp::endpoint ep6(asio::ip::address_v6::any(), REGSERVER_DEFAULT_PORT);

    logger::debug() << "Regserver bind on local endpoint " << ep;
    if (!comm::bind_socket(sock, ep, error_string_))
        return;
    // once bound, can start receiving datagrams.
    prepare_async_receive(sock);
    logger::debug() << "Bound socket on " << ep;

    logger::debug() << "Regserver bind on local endpoint " << ep6;
    if (!comm::bind_socket(sock6, ep6, error_string_))
        return;
    // once bound, can start receiving datagrams.
    error_string_ = "";
    prepare_async_receive(sock6);
    logger::debug() << "Bound socket on " << ep6;
}

void
registration_server::prepare_async_receive(asio::ip::udp::socket& s)
{
    asio::streambuf::mutable_buffers_type buffer = received_buffer.prepare(2048);
    s.async_receive_from(asio::buffer(buffer),
                         received_from,
                         boost::bind(&registration_server::udp_ready_read,
                                     this,
                                     asio::placeholders::error,
                                     asio::placeholders::bytes_transferred));
}

void
registration_server::udp_ready_read(const boost::system::error_code& error,
                                    size_t bytes_transferred)
{
    if (!error) {
        logger::debug() << "Received " << dec << bytes_transferred << " bytes via UDP link";
        byte_array b(asio::buffer_cast<const char*>(received_buffer.data()),
                     bytes_transferred);
        udp_dispatch(b, received_from);
        received_buffer.consume(bytes_transferred);
        if (received_from.address().is_v6()) {
            prepare_async_receive(sock6);
        } else {
            prepare_async_receive(sock);
        }
    } else {
        error_string_ = error.message();
        logger::warning() << "UDP read error - " << error_string_;
    }
}

bool
registration_server::send(const comm::endpoint& ep, byte_array const& msg)
{
    boost::system::error_code ec;
    size_t sent = sock.send_to(asio::buffer(msg.data(), msg.size()), ep, 0, ec);
    if (ec or sent < msg.size()) {
        error_string_ = ec.message();
    }
    return sent == msg.size();
}

void
registration_server::udp_dispatch(byte_array& msg, comm::endpoint const& srcep)
{
    logger::debug() << "Received " << dec << msg.size() << " byte message from " << srcep;

    // uint32_t magic, code;

    // magic = msg.as<big_uint32_t>()[0];

    // byte_array_iwrap<flurry::iarchive> read(msg);
    // read.archive().skip_raw_data(4);
    // read.archive() >> code;

    // if (magic != REG_MAGIC) {
    //     logger::debug() << "Received message from " << srcep << " with bad magic";
    //     return;
    // }

    // switch (code) {
    //     case REG_REQUEST | REG_INSERT1: return do_insert1(read, srcep);
    //     case REG_REQUEST | REG_INSERT2: return do_insert2(read, srcep);
    //     case REG_REQUEST | REG_LOOKUP: return do_lookup(read, srcep);
    //     case REG_REQUEST | REG_SEARCH: return do_search(read, srcep);
    //     case REG_REQUEST | REG_DELETE: return do_delete(read, srcep);
    //     default: logger::debug() << "Received message from " << srcep << " with bad request
    //     code";
    // }
}

void
registration_server::do_insert1(byte_array_iwrap<flurry::iarchive>& rxs,
                                comm::endpoint const& srcep)
{
    logger::debug() << "Insert1";

    // Decode the rest of the request message (after the 32-bit code)
    byte_array idi, nhi;
    rxs.archive() >> idi >> nhi;
    if (idi.is_empty()) {
        logger::debug() << "Received invalid Insert1 message";
        return;
    }

    // Compute and reply with an appropriate challenge.
    reply_insert1(srcep, idi, nhi);
}

/**
 * Send back the challenge cookie in our INSERT1 response,
 * in order to verify round-trip connectivity
 * before spending CPU time checking the client's signature.
 */
void
registration_server::reply_insert1(const comm::endpoint& srcep,
                                   const byte_array& idi,
                                   const byte_array& nhi)
{
    // Compute the correct challenge cookie for the message.
    // XX really should use a proper HMAC here.
    byte_array challenge = calc_cookie(srcep, idi, nhi);

    logger::debug() << "reply_insert1 challenge " << challenge;

    byte_array resp;
    {
        // resp.resize(4);
        // resp.as<big_uint32_t>()[0] = REG_MAGIC;

        // byte_array_owrap<flurry::oarchive> write(resp);
        // write.archive() << (REG_RESPONSE | REG_INSERT1) << nhi << challenge;
    }
    send(srcep, resp);
    logger::debug() << "reply_insert1 sent to " << srcep;
}

byte_array
registration_server::calc_cookie(const comm::endpoint& srcep,
                                 const byte_array& idi,
                                 const byte_array& nhi)
{
    // Make sure we have a host secret to key the challenge with
    // if (secret.is_empty()) {
    //     crypto::hash::value init;
    //     crypto::fill_random(init);
    //     secret = init;
    // }
    // assert(secret.size() == crypto::hash::size);

    // Compute the correct challenge cookie for the message.
    // XX really should use a proper HMAC here.
    byte_array resp;
    // {
    //     byte_array_owrap<flurry::oarchive> write(resp);
    //     write.archive() << secret << srcep << idi << nhi << secret;
    // }

    return resp; // crypto::sha256::hash(resp);
}

void
registration_server::do_insert2(byte_array_iwrap<flurry::iarchive>& rxs,
                                const comm::endpoint& srcep)
{
    logger::debug() << "Insert2";

    // Decode the rest of the request message (after the 32-bit code)
    byte_array idi, ni, chal, info, key, sig;
    rxs.archive() >> idi >> ni >> chal >> info >> key >> sig;
    if (idi.is_empty()) {
        logger::debug() << "Received invalid Insert2 message";
        return;
    }

    uia::peer_identity peerid(idi.as_string());

    // The client's INSERT1 contains the hash of its nonce;
    // the INSERT2 contains the actual nonce,
    // so that an eavesdropper can't easily forge an INSERT2
    // after seeing the client's INSERT1 fly past.
    byte_array nhi; //= crypto::sha256::hash(ni);

    // First check the challenge cookie:
    // if it is invalid (perhaps just because our secret expired),
    // just send back a new INSERT1 response.
    if (calc_cookie(srcep, idi, nhi) != chal) {
        logger::debug() << "Received Insert2 message with bad cookie";
        return reply_insert1(srcep, idi, nhi);
    }

    // See if we've already responded to a request with this cookie.
    if (contains(chalhash, chal)) {
        logger::debug() << "Received apparent replay of old Insert2 request";

        // Just return the previous response.
        // If the registered response is empty,
        // it means the client was bad so we're ignoring it:
        // in that case just silently drop the request.
        byte_array resp = chalhash[chal];
        if (!resp.is_empty()) {
            send(srcep, resp);
        }

        return;
    }

    // For now we only support RSA-based identities,
    // because DSA signature verification is much more costly.
    // XX would probably be good to send back an error response.
    uia::peer_identity identi(idi.as_string());
    // if (identi.key_scheme() != sss::peer_identity::scheme::rsa160) {
    //     logger::debug() << "Received Insert for unsupported ID scheme " << identi.scheme_name();
    //     chalhash.insert(make_pair(chal, byte_array()));
    //     return;
    // }

    // Parse the client's public key and make sure it matches its EID.
    if (!identi.set_key(key.as_string())) {
        logger::debug() << "Received bad identity from client " << srcep << " on insert2";
        chalhash.insert(make_pair(chal, byte_array()));
        return;
    }

    // Compute the hash of the message components the client signed.
    byte_array sigmsg;
    {
        byte_array_owrap<flurry::oarchive> write(sigmsg);
        write.archive() << idi << ni << chal << info;
    }

    // Verify the client's signature using his public key.
    // if (!identi.verify(crypto::sha256::hash(sigmsg), sig)) {
    //     logger::debug() << "Signature check for client " << srcep << " failed on insert2";
    //     chalhash.insert(make_pair(chal, byte_array()));
    //     return;
    // }

    // Insert an appropriate record into our in-memory client database.
    // This automatically replaces any existing record for the same ID,
    // in effect resetting the timeout for the client as well.
    registry_record* rec{new registry_record(*this, idi, nhi, srcep, info)};
    // Register record in the registration_server's ID-lookup table,
    // replacing any existing entry with this ID.
    registry_record* old = idhash[idi];
    if (old != nullptr) {
        logger::debug() << "Replacing existing record for " << idi;
        timeout_record(old);
    }
    idhash[idi] = rec;
    all_records_.insert(rec);

    // Register all our keywords in the registration_server's keyword table.
    register_keywords(true, rec);

    // Send a reply to the client indicating our timeout on its record,
    // so it knows how soon it will need to refresh the record.
    byte_array resp;
    {
        // resp.resize(4);
        // resp.as<big_uint32_t>()[0] = REG_MAGIC;

        // byte_array_owrap<flurry::oarchive> write(resp);
        // write.archive() << (REG_RESPONSE | REG_INSERT2) << nhi <<
        // registry_record::timeout_seconds
        //                 << srcep;
    }
    send(srcep, resp);

    logger::debug() << "Inserted record for " << peerid << " at " << srcep;
}

void
registration_server::do_lookup(byte_array_iwrap<flurry::iarchive>& rxs, const comm::endpoint& srcep)
{
    // Decode the rest of the lookup request.
    byte_array idi, nhi, idr;
    bool notify;
    rxs.archive() >> idi >> nhi >> idr >> notify;
    if (idi.is_empty()) {
        logger::debug() << "Received invalid Lookup message";
        return;
    }
    if (notify) {
        logger::debug() << "Lookup with notify";
    }

    // Lookup the initiator (caller).
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    auto reci = find_caller(srcep, idi, nhi);
    if (reci == nullptr)
        return;

    // Return the contents of the selected record, if any, to the caller.
    // If the target is not or is no longer registered
    // (e.g., because its record timed out since
    // the caller's last Lookup or Search request that found it),
    // respond to the initiator anyway indicating as such.
    auto recr = idhash[idr];
    reply_lookup(reci, REG_RESPONSE | REG_LOOKUP, idr, recr);

    // Send a response to the target as well, if found,
    // so that the two can perform UDP hole punching if desired.
    if (recr and notify) {
        reply_lookup(recr, REG_NOTIFY | REG_LOOKUP, idi, reci);
    }
}

void
registration_server::reply_lookup(registry_record* reci,
                                  uint32_t replycode,
                                  const byte_array& idr,
                                  registry_record* recr)
{
    logger::debug() << "Reply lookup " << replycode;

    byte_array resp;
    {
        // resp.resize(4);
        // resp.as<big_uint32_t>()[0] = REG_MAGIC;

        // byte_array_owrap<flurry::oarchive> write(resp);
        // bool known = (recr != nullptr);
        // write.archive() << replycode << reci->nhi << idr << known;
        // if (known) {
        //     write.archive() << recr->ep << recr->profile_info_;
        // }
    }
    send(reci->ep, resp);
}

template <typename InIt1, typename InIt2, typename OutIt>
OutIt
unordered_set_intersection(InIt1 b1, InIt1 e1, InIt2 b2, InIt2 e2, OutIt out)
{
    while (!(b1 == e1)) {
        if (!(std::find(b2, e2, *b1) == e2)) {
            *out = *b1;
            ++out;
        }
        ++b1;
    }

    return out;
}

void
registration_server::do_search(byte_array_iwrap<flurry::iarchive>& rxs, const comm::endpoint& srcep)
{
    // Decode the rest of the search request.
    byte_array idi, nhi;
    std::string search;
    rxs.archive() >> idi >> nhi >> search;
    if (idi.is_empty()) {
        logger::debug() << "Received invalid Search message";
        return;
    }

    // Lookup the initiator (caller) ID.
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    auto reci = find_caller(srcep, idi, nhi);
    if (reci == nullptr) {
        return;
    }

    // Break the search string into keywords.
    // We'll interpret them as an AND-set.
    std::vector<std::string> kwords;
    std::regex word_regex("(\\S+)");
    auto words_begin = std::sregex_iterator(search.begin(), search.end(), word_regex);
    auto words_end   = std::sregex_iterator();
    const int N = 2;
    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::smatch match     = *i;
        std::string match_str = match.str();
        if (match_str.size() >= N) {
            kwords.emplace_back(match_str);
        }
    }

    // Find the keyword with fewest matches to start with,
    // in order to make the set arithmetic reasonable efficient.
    decltype(all_records_) minset;
    string minkw;
    size_t mincount = INT_MAX;
    for (string kw : kwords) {
        if (!contains(keyword_records_, kw)) {
            minset.clear();
            mincount = 0;
            break;
        }
        auto set = keyword_records_[kw];
        if (set.size() < mincount) {
            minset   = set;
            mincount = set.size();
            minkw    = kw;
        }
    }
    logger::debug() << "Min keyword " << minkw << " set size " << mincount;

    // From there, narrow the minset further for each keyword.
    for (std::string kw : kwords) {
        if (minset.empty()) {
            break; // Can't get any smaller than this...
        }
        if (kw == minkw) {
            continue; // It's the one we started with
        }
        decltype(minset) outset;
        unordered_set_intersection(minset.begin(),
                                   minset.end(),
                                   keyword_records_[kw].begin(),
                                   keyword_records_[kw].end(),
                                   inserter(outset, outset.begin()));
        minset = outset;
    }
    logger::debug() << "Minset size " << minset.size();

    // If client supplied no keywords, (try to) return all records.
    auto const& results = kwords.empty() ? all_records_ : minset;

    // Limit the set of results to at most MAX_RESULTS.
    size_t nresults = results.size();
    bool complete = true;
    if (nresults > MAX_RESULTS) {
        nresults = MAX_RESULTS;
        complete = false;
    }

    // Return the IDs of the selected records to the caller.
    byte_array resp;
    {
        // resp.resize(4);
        // resp.as<big_uint32_t>()[0] = REG_MAGIC;

        // byte_array_owrap<flurry::oarchive> write(resp);
        // write.archive() << (REG_RESPONSE | REG_SEARCH) << nhi << search << complete << nresults;
        // for (auto rec : results) {
        //     logger::debug() << "Search result " << rec->id;
        //     write.archive() << rec->id;
        //     if (--nresults == 0)
        //         break;
        // }
    }
    assert(nresults == 0);
    send(srcep, resp);
}

void
registration_server::do_delete(byte_array_iwrap<flurry::iarchive>& rxs, comm::endpoint const& srcep)
{
    logger::debug() << "Received delete request";

    // Decode the rest of the delete request.
    byte_array idi, hashedNonce;
    rxs.archive() >> idi >> hashedNonce;
    if (idi.is_empty()) {
        logger::debug() << "Received invalid Delete message";
        return;
    }

    // Lookup the initiator (caller) ID.
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    auto reci = find_caller(srcep, idi, hashedNonce);
    if (reci == nullptr)
        return;

    // bool wasDeleted = idhash.count(idi) > 0;
    timeout_record(reci); // will wipe it from idhash table.

    // Response back notifying that the record was deleted.
    byte_array resp;
    {
        // resp.resize(4);
        // resp.as<big_uint32_t>()[0] = REG_MAGIC;

        // byte_array_owrap<flurry::oarchive> write(resp);
        // write.archive() << (REG_RESPONSE | REG_DELETE) << hashedNonce << wasDeleted;
    }
    send(srcep, resp);

    // XX Need to notify active listeners of the search results that one of the results is gone.
}

registry_record*
registration_server::find_caller(comm::endpoint const& ep,
                                 byte_array const& idi,
                                 byte_array const& nhi)
{
    // @TODO: list the existing records here before lookup?

    if (!contains(idhash, idi)) {
        logger::debug() << "Received request from non-registered caller";
        return nullptr;
    }
    auto reci = idhash[idi];
    if (ep != reci->ep) {
        logger::debug() << "Received request from wrong source endpoint " << ep << " expecting "
                        << reci->ep;
        return nullptr;
    }
    if (nhi != reci->nhi) {
        logger::debug() << "Received request with incorrect hashed nonce";
        return nullptr;
    }
    return reci;
}

void
registration_server::register_keywords(bool insert, internal::registry_record* rec)
{
    for (std::string kw : client_profile(rec->profile_info_).keywords()) {
        auto& set = keyword_records_[kw];
        if (insert) {
            set.insert(rec);
        } else {
            set.erase(rec);
            if (set.empty())
                keyword_records_.erase(kw);
        }
    }
}

// Our timeout expired - just delete this record.
void
registration_server::timeout_record(internal::registry_record* rec)
{
    logger::debug() << "Timed out record for " << uia::peer_identity(rec->id.as_string()) << " at " << rec->ep;
    register_keywords(false, rec);
    idhash.erase(rec->id);
    all_records_.erase(rec);
    delete rec;
}

} // routing namespace
} // uia namespace

//
// Main application entrypoint
//
int
main(int argc, char** argv)
{
    std::shared_ptr<sss::host> host(host::create()); // to create timer engines...
    uia::routing::registration_server regserver(host);
    regserver.run();
}
