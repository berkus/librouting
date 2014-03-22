//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2014, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "routing/registration_server.h"

namespace uia {
namespace routing {

registration_server::registration_server()
{
    server_ = make_shared<ssu::server>(host);
    server_->on_new_connection.connect([&] { on_new_connection(server); });
    bool listening = server_->listen("routing", "Overlay routing layer",
        "regserver-v1", "Registration server protocol");
    assert(listening);
}

void
registration_server::on_new_connection(shared_ptr<server> server)
{
    while (auto stream = server->accept())
    {
        stream.on_ready_read_record.connect([this] { on_incoming_record(stream); });
        sessions_.push_back(stream);
    }
}

void
registration_server::on_incoming_record(shared_ptr<stream> stream)
{
    peer_id remote_id = stream->remote_host_id();
    byte_array msg = stream->read_record();
    logger::debug() << "Received " << dec << msg.size() << " byte message from " << remote_id;

    uint32_t magic, code;

    msg.resize(4);
    magic = msg.as<big_uint32_t>()[0];

    if (magic != REG_MAGIC) {
        logger::debug() << "Received message from " << remote_id << " with bad magic";
        return;
    }

    byte_array_iwrap<flurry::iarchive> read(msg);
    read.archive().skip_raw_data(4);
    read.archive() >> code;

    switch (code)
    {
        case REG_REQUEST | REG_INSERT1:
            return do_insert1(read, stream);
        case REG_REQUEST | REG_INSERT2:
            return do_insert2(read, stream);
        case REG_REQUEST | REG_LOOKUP:
            return do_lookup(read, stream);
        case REG_REQUEST | REG_SEARCH:
            return do_search(read, stream);
        case REG_REQUEST | REG_DELETE:
            return do_delete(read, stream);
        default:
            logger::debug() << "Received message from " << remote_id << " with bad request code";
    }
}

void
registration_server::do_insert1(byte_array_iwrap<flurry::iarchive>& read,
                                shared_ptr<stream> stream)
{
    logger::debug() << "Insert1";

    // Decode the rest of the request message (after the 32-bit code)
    byte_array initiator_eid, initiator_hashed_nonce;
    read.archive() >> initiator_eid >> initiator_hashed_nonce;

    if (initiator_eid.is_empty() || initiator_hashed_nonce.is_empty())
    {
        logger::debug() << "Received invalid Insert1 message";
        return;
    }

    // Compute and reply with an appropriate challenge.
    reply_insert1(stream, initiator_eid, initiator_hashed_nonce);
}

/**
 * Send back the challenge cookie in our INSERT1 response,
 * in order to verify round-trip connectivity
 * before spending CPU time checking the client's signature.
 */
void
registration_server::reply_insert1(shared_ptr<stream> stream,
                                   const byte_array &initiator_eid,
                                   const byte_array &initiator_hashed_nonce)
{
    peer_id remote_id = stream->remote_host_id();
    // Compute the correct challenge cookie for the message.
    // really should use a proper HMAC here. -- that's provided by channel layer if possible
    byte_array challenge = calc_cookie(remote_id, initiator_eid, initiator_hashed_nonce);

    logger::debug() << "reply_insert1 challenge " << challenge;

    byte_array resp;
    {
        resp.resize(4);
        resp.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(resp);
        write.archive() << (REG_RESPONSE | REG_INSERT1) << initiator_hashed_nonce << challenge;
    }
    stream->write_record(resp);
    logger::debug() << "reply_insert1 sent to " << remote_id;
}

byte_array
registration_server::calc_cookie(const peer_id& eid,
                                 const byte_array &initiator_eid,
                                 const byte_array &initiator_hashed_nonce)
{
    // Make sure we have a host secret to key the challenge with
    if (secret.is_empty())
    {
        crypto::hash::value init;
        crypto::fill_random(init);
        secret = init;
    }
    assert(secret.size() == crypto::hash::size);

    // Compute the correct challenge cookie for the message.
    // XX really should use a proper HMAC here.
    byte_array resp;
    {
        byte_array_owrap<flurry::oarchive> write(resp);
        write.archive() << secret << eid << initiator_eid << initiator_hashed_nonce << secret;
    }

    return crypto::sha256::hash(resp);
}

void
registration_server::do_insert2(byte_array_iwrap<flurry::iarchive>& read,
                                shared_ptr<stream> stream)
{
    peer_id remote_id = stream->remote_host_id();

    logger::debug() << "Insert2";

    // Decode the rest of the request message (after the 32-bit code)
    byte_array initiator_eid, initiator_nonce, challenge, info, key, signature;
    read.archive() >> initiator_eid >> initiator_nonce >> challenge >> info >> key >> signature;
    if (initiator_eid.is_empty()) // @todo: read will throw exception on eos
    {
        logger::debug() << "Received invalid Insert2 message";
        return;
    }

    ssu::peer_id peerid(initiator_eid);

    // The client's INSERT1 contains the hash of its nonce;
    // the INSERT2 contains the actual nonce,
    // so that an eavesdropper can't easily forge an INSERT2
    // after seeing the client's INSERT1 fly past.
    byte_array initiator_hashed_nonce = crypto::sha256::hash(initiator_nonce);

    // First check the challenge cookie:
    // if it is invalid (perhaps just because our secret expired),
    // just send back a new INSERT1 response.
    if (calc_cookie(stream, initiator_eid, initiator_hashed_nonce) != challenge)
    {
        logger::debug() << "Received Insert2 message with bad cookie";
        return reply_insert1(stream, initiator_eid, initiator_hashed_nonce);
    }

    // See if we've already responded to a request with this cookie.
    if (contains(chalhash, challenge))
    {
        logger::debug() << "Received apparent replay of old Insert2 request";

        // Just return the previous response.
        // If the registered response is empty,
        // it means the client was bad so we're ignoring it:
        // in that case just silently drop the request.
        byte_array resp = chalhash[challenge];
        if (!resp.is_empty()) {
            stream->write_record(resp);
        }

        return;
    }

    // For now we only support RSA-based identities,
    // because DSA signature verification is much more costly.
    // @todo Support NaCl identity schemes (ecdsa etc).
    // @todo Would probably be good to send back an error response.
    ssu::identity identi(initiator_eid);
    if (identi.key_scheme() != ssu::identity::scheme::rsa160)
    {
        logger::debug() << "Received Insert2 for unsupported ID scheme " << identi.scheme_name();
        chalhash.insert(challenge, byte_array());
        return;
    }

    // Parse the client's public key and make sure it matches its EID.
    if (!identi.set_key(key))
    {
        logger::debug() << "Received bad identity from client " << remote_id << " on Insert2";
        chalhash.insert(challenge, byte_array());
        return;
    }

    // Compute the hash of the message components the client signed.
    byte_array sigmsg;
    {
        byte_array_owrap<flurry::oarchive> write(sigmsg);
        write.archive() << initiator_eid << initiator_nonce << challenge << info;
    }

    // Verify the client's signature using his public key.
    if (!identi.verify(crypto::sha256::hash(sigmsg), signature))
    {
        logger::debug() << "Signature check for client " << remote_id << " failed on Insert2";
        chalhash.insert(challenge, byte_array());
        return;
    }

    // Insert an appropriate record into our in-memory client database.
    // This automatically replaces any existing record for the same ID,
    // in effect resetting the timeout for the client as well.
    registry_record* rec{
        new registry_record(*this, initiator_eid, initiator_hashed_nonce, remote_id, info)};

    // Register record in the registration_server's ID-lookup table,
    // replacing any existing entry with this ID.
    registry_record* old = idhash[initiator_eid];
    if (old != nullptr)
    {
        logger::debug() << "Replacing existing record for " << initiator_eid;
        timeout_record(old);
    }
    idhash[initiator_eid] = rec;
    all_records_.insert(rec);

    // Register all our keywords in the registration_server's keyword table.
    register_keywords(true, rec);

    // Send a reply to the client indicating our timeout on its record,
    // so it knows how soon it will need to refresh the record.
    byte_array resp;
    {
        resp.resize(4);
        resp.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(resp);
        write.archive() << (REG_RESPONSE | REG_INSERT2) << initiator_hashed_nonce
            << registry_record::timeout_seconds << remote_id;
    }
    stream->write_record(resp);

    logger::debug() << "Inserted record for " << peerid << " at " << remote_id;
}

void
registration_server::do_lookup(byte_array_iwrap<flurry::iarchive>& read,
                               shared_ptr<stream> stream)
{
    // Decode the rest of the lookup request.
    byte_array initiator_eid, initiator_hashed_nonce, responder_eid;
    bool notify;
    read.archive() >> initiator_eid >> initiator_hashed_nonce >> responder_eid >> notify;
    if (initiator_eid.is_empty())
    {
        logger::debug() << "Received invalid Lookup message";
        return;
    }

    if (notify) {
        logger::debug() << "Lookup with notify";
    }

    // Look up the initiator (caller).
    //
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    //
    // @todo It's enough to send lookup requests with HUUGE responder_eid or nonce array headers
    // and cause memory overalloc in do_lookup() while reading from flurry.
    auto reci = find_caller(stream->remote_host_id(), initiator_eid, initiator_hashed_nonce);
    if (reci == nullptr) {
        return;
    }

    // Return the contents of the selected record, if any, to the caller.
    // If the target is not or is no longer registered
    // (e.g., because its record timed out since
    // the caller's last Lookup or Search request that found it),
    // respond to the initiator anyway indicating as such.
    auto recr = idhash[responder_eid];
    reply_lookup(reci, REG_RESPONSE | REG_LOOKUP, responder_eid, recr);

    // Send a response to the target as well, if found,
    // so that the two can perform UDP hole punching if desired.
    if (recr && notify) {
        reply_lookup(recr, REG_NOTIFY | REG_LOOKUP, initiator_eid, reci);
    }
}

void
registration_server::reply_lookup(registry_record *reci, uint32_t replycode,
                                  const byte_array &responder_eid, registry_record *recr)
{
    logger::debug() << "Reply lookup " << replycode;

    byte_array resp;
    {
        resp.resize(4);
        resp.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(resp);
        bool known = (recr != nullptr);
        write.archive() << replycode << reci->initiator_hashed_nonce << responder_eid << known;
        if (known) {
            write.archive() << recr->ep << recr->profile_info_;
        }
    }
    // send(reci->ep, resp):
    reci->stream->write_record(resp);
}

template <typename InIt1, typename InIt2, typename OutIt>
OutIt unordered_set_intersection(InIt1 b1, InIt1 e1, InIt2 b2, InIt2 e2, OutIt out)
{
    while (!(b1 == e1))
    {
        if (!(std::find(b2, e2, *b1) == e2))
        {
            *out = *b1;
            ++out;
        }
        ++b1;
    }
    return out;
}

void
registration_server::do_search(byte_array_iwrap<flurry::iarchive>& read,
                               shared_ptr<stream> stream)
{
    // Decode the rest of the search request.
    byte_array initiator_eid, initiator_hashed_nonce;
    std::string search;
    read.archive() >> initiator_eid >> initiator_hashed_nonce >> search;
    if (initiator_eid.is_empty())
    {
        logger::debug() << "Received invalid Search message";
        return;
    }

    // Lookup the initiator (caller) ID.
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    auto reci = find_caller(srcep, initiator_eid, initiator_hashed_nonce);
    if (reci == nullptr) {
        return;
    }

    // Break the search string into keywords.
    // We'll interpret them as an AND-set.
    std::vector<std::string> kwords;
    std::regex word_regex("(\\S+)");
    auto words_begin = std::sregex_iterator(search.begin(), search.end(), word_regex);
    auto words_end = std::sregex_iterator();
    const int N = 2; // Minimum word size
    for (std::sregex_iterator i = words_begin; i != words_end; ++i)
    {
        std::smatch match = *i;
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
    for (string kw : kwords)
    {
        if (!contains(keyword_records_, kw))
        {
            minset.clear();
            mincount = 0;
            break;
        }
        auto set = keyword_records_[kw];
        if (set.size() < mincount)
        {
            minset = set;
            mincount = set.size();
            minkw = kw;
        }
    }
    logger::debug() << "Min keyword '" << minkw << "' set size " << mincount;

    // From there, narrow the minset further for each keyword.
    for (std::string kw : kwords)
    {
        if (minset.empty()) {
            break;  // Can't get any smaller than this...
        }
        if (kw == minkw) {
            continue; // It's the one we started with
        }
        decltype(minset) outset;
        unordered_set_intersection(minset.begin(), minset.end(),
            keyword_records_[kw].begin(), keyword_records_[kw].end(),
            inserter(outset, outset.begin()));
        minset = outset;
    }
    logger::debug() << "Minset size " << minset.size();

    // If client supplied no keywords, (try to) return all records.
    auto const& results = kwords.empty() ? all_records_ : minset;

    // Limit the set of results to at most MAX_RESULTS.
    size_t nresults = results.size();
    bool complete = true;
    if (nresults > MAX_RESULTS)
    {
        nresults = MAX_RESULTS;
        complete = false;
    }

    // Return the IDs of the selected records to the caller.
    byte_array resp;
    {
        resp.resize(4);
        resp.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(resp);
        write.archive() << (REG_RESPONSE | REG_SEARCH) << initiator_hashed_nonce
            << search << complete << nresults;

        for (auto rec : results)
        {
            logger::debug() << "Search result " << rec->id;
            write.archive() << rec->id;
            if (--nresults == 0) {
                break;
            }
        }
    }
    assert(nresults == 0);
    stream->write_record(resp);
}

void
registration_server::do_delete(byte_array_iwrap<flurry::iarchive>& read,
                               shared_ptr<stream> stream)
{
    logger::debug() << "Received delete request";

    // Decode the rest of the delete request.
    byte_array initiator_eid, hashed_nonce;
    read.archive() >> initiator_eid >> hashed_nonce;
    if (initiator_eid.is_empty())
    {
        logger::debug() << "Received invalid Delete message";
        return;
    }

    // Lookup the initiator (caller) ID.
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    auto reci = find_caller(srcep, initiator_eid, hashed_nonce);
    if (reci == nullptr) {
        return;
    }

    bool was_deleted = idhash.count(initiator_eid) > 0;
    timeout_record(reci); // will wipe it from idhash table.

    // Response back notifying that the record was deleted.
    byte_array resp;
    {
        resp.resize(4);
        resp.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(resp);
        write.archive() << (REG_RESPONSE | REG_DELETE) << hashed_nonce << was_deleted;
    }
    stream->write_record(resp);

    // XX Need to notify active listeners of the search results that one of the results is gone.
}

registry_record*
registration_server::find_caller(const ssu::endpoint &ep, const byte_array &initiator_eid,
                                 const byte_array &initiator_hashed_nonce)
{
    // @TODO: list the existing records here before lookup?

    if (!contains(idhash, initiator_eid))
    {
        logger::debug() << "Received request from non-registered caller";
        return nullptr;
    }
    auto reci = idhash[initiator_eid];
    if (ep != reci->ep)
    {
        logger::debug() << "Received request from wrong source endpoint " << ep
            << " expecting " << reci->ep;
        return nullptr;
    }
    if (initiator_hashed_nonce != reci->initiator_hashed_nonce)
    {
        logger::debug() << "Received request with incorrect hashed nonce";
        return nullptr;
    }
    return reci;
}

void
registration_server::register_keywords(bool insert, internal::registry_record* rec)
{
    for (std::string kw : client_profile(rec->profile_info_).keywords())
    {
        auto& set = keyword_records_[kw];
        if (insert) {
            set.insert(rec);
        }
        else
        {
            set.erase(rec);
            if (set.empty()) {
                keyword_records_.erase(kw);
            }
        }
    }
}

// Our timeout expired - just delete this record.
void
registration_server::timeout_record(internal::registry_record* rec)
{
    logger::debug() << "Timed out record for " << peer_id(rec->id) << " at " << rec->ep;
    register_keywords(false, rec);
    idhash.erase(rec->id);
    all_records_.erase(rec);
    delete rec;
}

} // routing namespace
} // uia namespace
