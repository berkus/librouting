#include "routing/private/regserver_client.h"
#include "ssu/host.h"
#include "comm/socket.h"
#include "krypto/sha256_hash.h"

namespace bp = boost::posix_time;
using namespace std;

namespace uia {
namespace routing {
namespace internal {

/**
 * Many NATs drop UDP mappings after about 15 minutes, keep re-registering at about half this
 * interval to keep holes punched.
 */
const boost::posix_time::time_duration regserver_client::max_rereg = bp::minutes(15);

regserver_client::regserver_client(ssu::host *h)
    : client()
    , host_(h)
    , state_(state::idle)
    , resolver_(h->get_io_service())
    , idi(h->host_identity().id().id())
    , retry_timer_(h)
    , rereg_timer_(h)
{
    retry_timer_.on_timeout.connect([this](bool failed) { timeout(failed); });
    rereg_timer_.on_timeout.connect([this](bool) { rereg_timeout(); });

    host_->coordinator->add_routing_client(this);
    host_->coordinator->on_routing_client_created(this);
}

regserver_client::~regserver_client()
{
    // First disconnect and cancel any outstanding lookups.
    disconnect();

    // Notify anyone interested of our upcoming destruction.
    host_->coordinator->on_routing_client_deleted(this);
    host_->coordinator->remove_routing_client(this);
    host_->coordinator->clear_nonce(nhi);
}

void regserver_client::fail(const std::string &err)
{
    error_string_ = err;
    disconnect();
}

void regserver_client::disconnect()
{
    if (state_ == state::idle)
        return;

    logger::debug() << this << "disconnect";
    send_delete();

    // Fail all outstanding lookup and search requests
    // XX provide a better error indication?
    for (const ssu::peer_id &id : lookups)
        on_lookup_done(id, uia::comm::endpoint(), client_profile());
    for (const ssu::peer_id &id : punches)
        on_lookup_done(id, uia::comm::endpoint(), client_profile());
    for (const std::string &text : searches)
        on_search_done(text, std::vector<ssu::peer_id>(), true);

    state_ = state::idle;
    addrs.clear();
    ni.clear();
    nhi.clear();
    chal.clear();
    key.clear();
    sig.clear();
    lookups.clear();
    punches.clear();
    searches.clear();
    retry_timer_.stop();
    rereg_timer_.stop();

    // Notify the user that we're not (or no longer) registered
    on_disconnected();
}

void regserver_client::register_at(const std::string &srvname, uint16_t srvport)
{
    assert(state_ == state::idle);
    logger::debug() << "Register at " << srvname << ":" << srvport;

    this->srvname = srvname;
    this->srvport = srvport;
    reregister();
}

void regserver_client::reregister()
{
    assert(!srvname.empty());
    assert(srvport != 0);

    logger::debug() << "Re-register on " << srvname << ":" << srvport;

    // Clear any previous nonce we may have used
    if (!ni.is_empty()) {
        host_->coordinator->clear_nonce(nhi);
        ni.clear();
        nhi.clear();
    }

    boost::system::error_code ec;
    boost::asio::ip::address addr = boost::asio::ip::address::from_string(srvname, ec);
    if (ec) {
        // Lookup the server hostname
        logger::debug() << "Looking up rendezvous server address.";
        state_ = state::resolve;
        boost::asio::ip::udp::resolver::query query1(srvname, "");
        resolver_.async_resolve(query1, [this](const boost::system::error_code& ec,
                                               boost::asio::ip::udp::resolver::iterator ep_it)
        {
            got_resolve_results(ec, ep_it);
        });
        return;
    }

    // Just use the IP address we were given in string form
    logger::debug() << "Using plain rendezvous server address.";
    addrs.clear();
    addrs.emplace_back(uia::comm::endpoint(addr, srvport));

    go_insert1();
}

void
regserver_client::got_resolve_results(const boost::system::error_code& ec,
    boost::asio::ip::udp::resolver::iterator ep_it)
{
    if (!ec) {
        for (boost::asio::ip::udp::resolver::iterator end; ep_it != end; ++ep_it)
        {
            // possible lookup key - ep_it->host_name()
            addrs.emplace_back(comm::endpoint(ep_it->endpoint().address(), srvport));
        }
    } else {
        return fail(ec.message());
    }

    logger::debug() << "Primary rendezvous server address " << addrs[0];

    go_insert1();
}

void regserver_client::go_insert1()
{
    // Create our random nonce and its hash, if not done already,
    // and register this client to receive replies keyed on this nonce.
    if (ni.is_empty()) {
        ni.resize(crypto::SHA256_HASH_LEN);
        crypto::fill_random(ni.as_vector());
        nhi = crypto::sha256::hash(ni);
        host_->coordinator->insert_nonce(nhi, this);
    }
    assert(ni.size() == crypto::SHA256_HASH_LEN);
    assert(nhi.size() == crypto::SHA256_HASH_LEN);

    // Enter Insert1 state and start sending
    state_ = state::insert1;
    send_insert1();
    retry_timer_.start();
}

void regserver_client::send_insert1()
{
    logger::debug() << "Insert1";

    // Send our Insert1 message
    byte_array msg;
    {
        msg.resize(4);
        msg.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(msg);
        write.archive() << (REG_REQUEST | REG_INSERT1) << idi << nhi;
    }
    send(msg);
}

void regserver_client::got_insert1_reply(byte_array_iwrap<flurry::iarchive>& is)
{
    logger::debug() << "Insert1 reply";

    // Decode the rest of the reply
    is.archive() >> chal;
    if (chal.is_empty() /*rs.status() != rs.Ok*/) {
        logger::debug() << "Got invalid Insert1 reply";
        return;
    }

    // Looks good - go to Insert2 state.
    logger::debug() << "Insert1 reply looks good!";
    go_insert2();
}

/**
 * Serialize client profile into a byte_array type.
 */
byte_array info_blob(client_profile const& profile)
{
    byte_array result;
    byte_array_owrap<flurry::oarchive> write(result);
    write.archive() << profile;
    return result;
}

void regserver_client::go_insert2()
{
    logger::debug() << "Insert2";

    // Find our serialized public key to send to the server.
    ssu::identity identi = host_->host_identity();
    key = identi.public_key();

    // Compute the hash of the message components to be signed.
    byte_array pack;
    {
        byte_array_owrap<flurry::oarchive> write(pack);
        write.archive() << idi << ni << chal << info_blob(inf);
    }

    // Generate our signature.
    sig = identi.sign(crypto::sha256::hash(pack));
    assert(!sig.is_empty());

    state_ = state::insert2;
    send_insert2();
    retry_timer_.start();
}

void regserver_client::send_insert2()
{
    logger::debug() << "Insert2 reply";

    // Send our Insert2 message
    byte_array msg;
    {
        msg.resize(4);
        msg.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(msg);
        write.archive() << (REG_REQUEST | REG_INSERT2) << idi << ni << chal << info_blob(inf)
                        << key << sig;
    }
    send(msg);
}

void regserver_client::got_insert2_reply(byte_array_iwrap<flurry::iarchive>& is)
{
    // Decode the rest of the reply
    int32_t life_secs;
    comm::endpoint public_ep;
    is.archive() >> life_secs >> public_ep;
    // if (rs.status() != rs.Ok) {
    //     logger::debug() << this << "got invalid Insert2 reply";
    //     return;
    // }

    // Looks good - consider ourselves registered.
    state_ = state::registered;

    // Re-register when half the lifetime of our entry has expired.
    const boost::posix_time::time_duration life{bp::seconds(life_secs)};
    auto rereg = std::min(life, max_rereg);
    rereg_timer_.start(rereg);

    // Notify anyone interested.
    logger::debug() << "Registered with " << srvname << " for " << life_secs << " seconds";
    logger::debug() << "My public endpoint is " << public_ep;
    on_ready();
}

void regserver_client::lookup(const ssu::peer_id& idtarget, bool notify)
{
    assert(is_registered());

    if (notify) {
        punches.insert(idtarget);
    }
    else {
        lookups.insert(idtarget);
    }
    send_lookup(idtarget, notify);
    retry_timer_.start();
}

void regserver_client::send_lookup(const ssu::peer_id& idtarget, bool notify)
{
    logger::debug() << "Send lookup for ID " << idtarget;

    // Prepare the Lookup message
    byte_array msg;
    {
        msg.resize(4);
        msg.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(msg);
        write.archive() << (REG_REQUEST | REG_LOOKUP) << idi << nhi << idtarget.id() << notify;
    }
    send(msg);
}

void regserver_client::got_lookup_reply(byte_array_iwrap<flurry::iarchive>& is, bool isnotify)
{
    logger::debug() << "got_lookup_reply " << (isnotify ? "NOTIFY" : "RESPONSE");

    // Decode the rest of the reply
    byte_array targetid, targetinfo;
    bool success;
    comm::endpoint targetloc;
    is.archive() >> targetid >> success;
    if (success) {
        is.archive() >> targetloc >> targetinfo;
    }
    // if (rs.status() != rs.Ok) {
    //     logger::debug() << this << "got invalid Lookup reply";
    //     return;
    // }
    client_profile reginfo(targetinfo);

    // If it's an async lookup notification from the server,
    // just forward it to anyone listening on our on_lookup_notify signal.
    if (isnotify)
        return on_lookup_notify(targetid, targetloc, reginfo);

    // Otherwise, it should be a response to a lookup request.
    if (!(contains(lookups, targetid) || contains(punches, targetid))) {
        logger::debug() << "Useless lookup result";
        return;
    }
    logger::debug() << "Processed lookup for " << ssu::peer_id(targetid);
    lookups.erase(targetid);
    punches.erase(targetid);
    on_lookup_done(targetid, targetloc, reginfo);
}

void regserver_client::search(const std::string &text)
{
    assert(is_registered());

    searches.insert(text);
    send_search(text);
    retry_timer_.start();
}

void regserver_client::send_search(const std::string &text)
{
    // Prepare the Lookup message
    byte_array msg;
    {
        msg.resize(4);
        msg.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(msg);
        write.archive() << (REG_REQUEST | REG_SEARCH) << idi << nhi << text;
    }
    send(msg);
}

void regserver_client::got_search_reply(byte_array_iwrap<flurry::iarchive>& is)
{
    // Decode the first part of the reply
    std::string text;
    bool complete;
    int32_t nresults;
    is.archive() >> text >> complete >> nresults;
    if (/*rs.status() != rs.Ok ||*/ nresults < 0) {
        logger::debug() << "Got invalid Search reply";
        return;
    }

    // Make sure we actually did the indicated search
    if (!contains(searches, text)) {
        logger::debug() << "regserver_client: useless Search result";
        return;
    }

    // Decode the list of result IDs
    // @todo Change this into a single flurry read
    vector<ssu::peer_id> ids;
    for (int i = 0; i < nresults; i++) {
        ssu::peer_id id;
        is.archive() >> id;
        // if (rs.status() != rs.Ok) {
        //     logger::debug() << this << "got invalid Search result ID";
        //     return;
        // }
        ids.emplace_back(id);
    }

    searches.erase(text);
    on_search_done(text, ids, complete);
}

void regserver_client::send_delete()
{
    logger::debug() << "Send delete notice";

    // Prepare the Delete message
    byte_array msg;
    {
        msg.resize(4);
        msg.as<big_uint32_t>()[0] = REG_MAGIC;

        byte_array_owrap<flurry::oarchive> write(msg);
        write.archive() << (REG_REQUEST | REG_DELETE) << idi << nhi;
    }
    send(msg);
}

void regserver_client::got_delete_reply(byte_array_iwrap<flurry::iarchive>& is)
{
    // Ignore.
    logger::debug() << "Got delete reply, ignored";
}

void regserver_client::send(const byte_array &msg)
{
    logger::file_dump(msg, "sending packet to regserver");

    // Send the message to all addresses we know for the server,
    // using all of the currently active network sockets.
    // XXX should only do this during initial discovery!!
    auto socks = host_->active_sockets();
    if (socks.empty()) {
        logger::warning() << "No active network sockets available";
    }
    for (auto sock : socks)
    {
        for (auto addr : addrs)
        {
            addr.port(srvport); // ?? @fixme
            sock->send(addr, msg);
        }
    }
}

void regserver_client::timeout(bool failed)
{
    switch (state_) {
        case state::idle:
        case state::resolve:
            break;
        case state::insert1:
        case state::insert2:
            if (failed && !persist) {
                fail("Timeout connecting to registration server");
            } else {
                if (state_ == state::insert1) {
                    send_insert1();
                }
                else {
                    send_insert2();
                }
                retry_timer_.restart();
            }
            break;
        case state::registered:
            // Timeout on a Lookup or Search.
            if (lookups.empty() && punches.empty() && searches.empty()) {
                // Nothing to do - don't bother with the timer.
                retry_timer_.stop();
            } else if (failed) {
                // Our regserver is apparently no longer responding.
                // Disconnect (and try to re-connect if persistent).
                fail("Registration server no longer responding");
                if (persist)
                    reregister();
            } else {
                // Re-send all outstanding requests
                for (const ssu::peer_id &id : lookups) {
                    send_lookup(id, false);
                }
                for (const ssu::peer_id &id : punches) {
                    send_lookup(id, true);
                }
                for (const std::string &text : searches) {
                    send_search(text);
                }
                retry_timer_.restart();
            }
            break;
    }
}

void regserver_client::rereg_timeout()
{
    // Time to re-register!
    reregister();
}

} // internal namespace
} // routing namespace
} // uia namespace
