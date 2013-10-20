#include "regserver.h"
#include "logging.h"
#include "sha256_hash.h"

constexpr uint16_t REGSERVER_DEFAULT_PORT = 9669;

#define TIMEOUT_SEC (1*60*60)   // Records last 1 hour
#define MAX_RESULTS 100     // Maximum number of search results

// 'Nrs': Netsteria registration server
constexpr ssu::magic_t REG_MAGIC = 0x004e7273;

#define REG_REQUEST     0x100   // Client-to-server request
#define REG_RESPONSE    0x200   // Server-to-client response
#define REG_NOTIFY      0x300   // Server-to-client async callback

#define REG_INSERT1     0x00    // Insert entry - preliminary request
#define REG_INSERT2     0x01    // Insert entry - authenticated request
#define REG_LOOKUP      0x02    // Lookup host by ID, optionally notify
#define REG_SEARCH      0x03    // Search entry by keyword
#define REG_DELETE      0x04    // Remove registration record, sent by client upon exit

namespace uia {
namespace routing {

// registration_server implementation
// @TODO: bind ipv6 socket

registration_server::registration_server()
    : sock(io_service_)
{
    boost::asio::ip::udp::endpoint ep(boost::asio::ip::address_v4::any(), REGSERVER_DEFAULT_PORT);
    logger::debug() << "regserver bind on local endpoint " << ep;
    boost::system::error_code ec;
    sock.open(ep.protocol(), ec);
    if (ec) {
        error_string_ = ec.message();
        logger::warning() << ec;
        return;
    }
    sock.bind(ep, ec);
    if (ec) {
        error_string_ = ec.message();
        logger::warning() << ec;
        return;
    }
    // once bound, can start receiving datagrams.
    error_string_ = "";
    prepare_async_receive();
    logger::debug() << "Bound socket on " << ep;
}

void
registration_server::prepare_async_receive()
{
    boost::asio::streambuf::mutable_buffers_type buffer = received_buffer.prepare(2048);
    sock.async_receive_from(
        boost::asio::buffer(buffer),
        received_from,
        boost::bind(&registration_server::udp_ready_read, this,
          boost::asio::placeholders::error,
          boost::asio::placeholders::bytes_transferred));
}

void
registration_server::udp_ready_read(const boost::system::error_code& error, size_t bytes_transferred)
{
    if (!error)
    {
        logger::debug() << "Received " << bytes_transferred << " bytes via UDP link";
        byte_array b(boost::asio::buffer_cast<const char*>(received_buffer.data()), bytes_transferred);
        udpDispatch(b, received_from);
        received_buffer.consume(bytes_transferred);
        prepare_async_receive();
    }
    else
    {
        error_string_ = error.message();
        logger::warning() << "UDP read error - " << error_string_;
    }
}

bool
registration_server::send(const ssu::endpoint& ep, byte_array const& msg)
{
    boost::system::error_code ec;
    size_t sent = sock.send_to(boost::asio::buffer(msg.data(), msg.size()), ep, 0, ec);
    if (ec or sent < msg.size()) {
        error_string_ = ec.message();
    }
    return sent == msg.size();
}

void
registration_server::udpDispatch(byte_array &msg, const ssu::endpoint &srcep)
{
    logger::debug() << "Received " << msg.size() << " byte message from " << srcep;

    uint32_t magic, code;
    byte_array_iwrap<flurry::iarchive> read(msg);
    read.archive() >> magic >> code;

    if (magic != REG_MAGIC) {
        logger::debug() << "Received message from " << srcep << " with bad magic";
        return;
    }

    switch (code) {
    case REG_REQUEST | REG_INSERT1:
        return doInsert1(read, srcep);
    case REG_REQUEST | REG_INSERT2:
        return doInsert2(read, srcep);
    case REG_REQUEST | REG_LOOKUP:
        return doLookup(read, srcep);
    case REG_REQUEST | REG_SEARCH:
        return doSearch(read, srcep);
    case REG_REQUEST | REG_DELETE:
        return doDelete(read, srcep);
    default:
        logger::debug() << "Received message from " << srcep << " with bad request code";
    }
}

void
registration_server::doInsert1(byte_array_iwrap<flurry::iarchive>& rxs, const ssu::endpoint &srcep)
{
    logger::debug() << this << "Insert1";

    // Decode the rest of the request message (after the 32-bit code)
    byte_array idi, nhi;
    rxs.archive() >> idi >> nhi;
    if (idi.is_empty()) {
        logger::debug() << "Received invalid Insert1 message";
        return;
    }

    // Compute and reply with an appropriate challenge.
    replyInsert1(srcep, idi, nhi);
}

/**
 * Send back the challenge cookie in our INSERT1 response,
 * in order to verify round-trip connectivity
 * before spending CPU time checking the client's signature.
 */
void
registration_server::replyInsert1(const ssu::endpoint &srcep, const byte_array &idi, const byte_array &nhi)
{
    // Compute the correct challenge cookie for the message.
    // XX really should use a proper HMAC here.
    byte_array challenge = calcCookie(srcep, idi, nhi);

    logger::debug() << this << "replyInsert1 challenge" << challenge;

    byte_array resp;
    byte_array_owrap<flurry::oarchive> write(resp);
    write.archive() << REG_MAGIC << (uint32_t)(REG_RESPONSE | REG_INSERT1) << nhi << challenge;
    send(srcep, resp);
    logger::debug() << this << "replyInsert1 sent to" << srcep;
}

byte_array
registration_server::calcCookie(const ssu::endpoint &srcep, const byte_array &idi, const byte_array &nhi)
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
    ssu::crypto::sha256 chalsha;

    byte_array resp;
    byte_array_owrap<flurry::oarchive> write(resp);
    write.archive() << secret << srcep << idi << nhi << secret;

    return chalsha.final();
}

void
registration_server::doInsert2(byte_array_iwrap<flurry::iarchive>& rxs, const ssu::endpoint &srcep)
{
    logger::debug() << this << "Insert2";

    // Decode the rest of the request message (after the 32-bit code)
    byte_array idi, ni, chal, info, key, sig;
    rxs.archive() >> idi >> ni >> chal >> info >> key >> sig;
    if (idi.is_empty()) {
        logger::debug("Received invalid Insert2 message");
        return;
    }

    ssu::peer_id peerid(idi);

    // The client's INSERT1 contains the hash of its nonce;
    // the INSERT2 contains the actual nonce,
    // so that an eavesdropper can't easily forge an INSERT2
    // after seeing the client's INSERT1 fly past.
    byte_array nhi = ssu::crypto::sha256::hash(ni);

    // First check the challenge cookie:
    // if it is invalid (perhaps just because our secret expired),
    // just send back a new INSERT1 response.
    if (calcCookie(srcep, idi, nhi) != chal) {
        logger::debug() << "Received Insert2 message with bad cookie";
        return replyInsert1(srcep, idi, nhi);
    }

    // See if we've already responded to a request with this cookie.
    if (chalhash.contains(chal)) {
        logger::debug() << "Received apparent replay of old Insert2 request";

        // Just return the previous response.
        // If the registered response is empty,
        // it means the client was bad so we're ignoring it:
        // in that case just silently drop the request.
        byte_array resp = chalhash[chal];
        if (!resp.isEmpty())
            sock.writeDatagram(resp, srcep.addr, srcep.port);

        return;
    }

    // For now we only support RSA-based identities,
    // because DSA signature verification is much more costly.
    // XX would probably be good to send back an error response.
    Ident identi(idi);
    if (identi.scheme() != identi.RSA160) {
        logger::debug() << "Received Insert for unsupported ID scheme" << identi.scheme();
        chalhash.insert(chal, byte_array());
        return;
    }

    // Parse the client's public key and make sure it matches its EID.
    if (!identi.setKey(key))
    {
        logger::debug() << "Received bad identity from client" << srcep << "on insert";
        chalhash.insert(chal, byte_array());
        return;
    }

    // Compute the hash of the message components the client signed.
    ssu::crypto::sha256 sigsha;
    XdrStream sigwxs(&sigsha);
    sigwxs << idi << ni << chal << info;

    // Verify the client's signature using his public key.
    if (!identi.verify(sigsha.final(), sig))
    {
        logger::debug() << "Signature check for client" << srcep << "failed on Insert2";
        chalhash.insert(chal, byte_array());
        return;
    }

    // Insert an appropriate record into our in-memory client database.
    // This automatically replaces any existing record for the same ID,
    // in effect resetting the timeout for the client as well.
    (void)new registry_record(this, idi, nhi, srcep, info);

    // Send a reply to the client indicating our timeout on its record,
    // so it knows how soon it will need to refresh the record.
    byte_array resp;
    byte_array_owrap<flurry::oarchive> write(resp);
    write.archive() << REG_MAGIC << (uint32_t)(REG_RESPONSE | REG_INSERT2) << nhi << (uint32_t)TIMEOUT_SEC << srcep;
    send(srcep, resp);

    logger::debug() << "Inserted record for" << peerid << "at" << srcep;
}

void
registration_server::doLookup(byte_array_iwrap<flurry::iarchive>& rxs, const ssu::endpoint &srcep)
{
    // Decode the rest of the lookup request.
    byte_array idi, nhi, idr;
    bool notify;
    rxs >> idi >> nhi >> idr >> notify;
    if (rxs.status() != rxs.Ok || idi.isEmpty()) {
        logger::debug("Received invalid Lookup message");
        return;
    }
    if (notify)
        logger::debug("Lookup with notify");

    // Lookup the initiator (caller).
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    registry_record *reci = findCaller(srcep, idi, nhi);
    if (reci == nullptr)
        return;

    // Return the contents of the selected record, if any, to the caller.
    // If the target is not or is no longer registered
    // (e.g., because its record timed out since
    // the caller's last Lookup or Search request that found it),
    // respond to the initiator anyway indicating as such.
    registry_record *recr = idhash.value(idr);
    replyLookup(reci, REG_RESPONSE | REG_LOOKUP, idr, recr);

    // Send a response to the target as well, if found,
    // so that the two can perform UDP hole punching if desired.
    if (recr && notify)
        replyLookup(recr, REG_NOTIFY | REG_LOOKUP, idi, reci);
}

void
registration_server::replyLookup(registry_record *reci, uint32_t replycode, const byte_array &idr, registry_record *recr)
{
    logger::debug() << this << "replyLookup" << replycode;

    byte_array resp;
    XdrStream wxs(&resp, QIODevice::WriteOnly);
    bool known = (recr != nullptr);
    wxs << REG_MAGIC << replycode << reci->nhi << idr << known;
    if (known)
        wxs << recr->ep << recr->info;
    send(reci->ep, resp);
}

void
registration_server::doSearch(byte_array_iwrap<flurry::iarchive>& rxs, const ssu::endpoint &srcep)
{
    // Decode the rest of the search request.
    byte_array idi, nhi;
    QString search;
    rxs >> idi >> nhi >> search;
    if (rxs.status() != rxs.Ok || idi.isEmpty()) {
        logger::debug("Received invalid Search message");
        return;
    }

    // Lookup the initiator (caller) ID.
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    registry_record *reci = findCaller(srcep, idi, nhi);
    if (reci == nullptr)
        return;

    // Break the search string into keywords.
    // We'll interpret them as an AND-set.
    QStringList kwords = 
        search.split(QRegExp("\\W+"), QString::SkipEmptyParts);

    // Find the keyword with fewest matches to start with,
    // in order to make the set arithmetic reasonable efficient.
    QSet<registry_record*> minset;
    QString minkw;
    int mincount = INT_MAX;
    foreach (QString kw, kwords) {
        QSet<registry_record*> set = kwhash.value(kw);
        if (set.size() < mincount) {
            minset = set;
            mincount = set.size();
            minkw = kw;
        }
    }
    logger::debug() << "Min keyword" << minkw << "set size" << mincount;

    // From there, narrow the minset further for each keyword.
    foreach (QString kw, kwords) {
        if (minset.isEmpty())
            break;  // Can't get any smaller than this...
        if (kw == minkw)
            continue; // It's the one we started with
        minset.intersect(kwhash[kw]);
    }
    logger::debug() << "Minset size" << minset.size();

    // If client supplied no keywords, (try to) return all records.
    const QSet<registry_record*>& results = kwords.isEmpty() ? allrecords : minset;

    // Limit the set of results to at most MAX_RESULTS.
    qint32 nresults = results.size();
    bool complete = true;
    if (nresults > MAX_RESULTS) {
        nresults = MAX_RESULTS;
        complete = false;
    }

    // Return the IDs of the selected records to the caller.
    byte_array resp;
    XdrStream wxs(&resp, QIODevice::WriteOnly);
    wxs << REG_MAGIC << (quint32)(REG_RESPONSE | REG_SEARCH)
        << nhi << search << complete << nresults;
    foreach (registry_record *rec, results) {
        logger::debug() << "search result" << rec->id;
        wxs << rec->id;
        if (--nresults == 0)
            break;
    }
    assert(nresults == 0);
    send(srcep, resp);
}

void
registration_server::doDelete(byte_array_iwrap<flurry::iarchive>& rxs, const ssu::endpoint& srcep)
{
    logger::debug() << "Received delete request";

    // Decode the rest of the delete request.
    byte_array idi, hashedNonce;
    rxs >> idi >> hashedNonce;
    if (rxs.status() != rxs.Ok || idi.isEmpty()) {
        logger::debug("Received invalid Delete message");
        return;
    }

    // Lookup the initiator (caller) ID.
    // To protect us and our clients from DoS attacks,
    // the caller must be registered with the correct source endpoint.
    registry_record *reci = findCaller(srcep, idi, hashedNonce);
    if (reci == nullptr)
        return;

    bool wasDeleted = idhash.count(idi) > 0;
    delete reci; // will wipe it from idhash table.

    // Response back notifying that the record was deleted.
    byte_array resp;
    XdrStream wxs(&resp, QIODevice::WriteOnly);
    wxs << REG_MAGIC << (quint32)(REG_RESPONSE | REG_DELETE) << hashedNonce << wasDeleted;
    send(srcep, resp);

    // XX Need to notify active listeners of the search results that one of the results is gone.
}

registry_record*
registration_server::findCaller(const ssu::endpoint &ep, const byte_array &idi, const byte_array &nhi)
{
    // @TODO: list the existing records here before lookup?

    registry_record *reci = idhash.value(idi);
    if (reci == nullptr) {
        logger::debug("Received request from non-registered caller");
        return nullptr;
    }
    if (ep != reci->ep) {
        logger::debug() << "Received request from wrong source endpoint" << ep << "expecting" << reci->ep;
        return nullptr;
    }
    if (nhi != reci->nhi) {
        logger::debug("Received request with incorrect hashed nonce");
        return nullptr;
    }
    return reci;
}

//=====================================================================================================================
// registry_record implementation
//=====================================================================================================================
namespace internal  {

registry_record::registry_record(registration_server *srv,
        const byte_array &id, const byte_array &nhi,
        const endpoint &ep, const byte_array &info)
    : srv(srv)
    , id(id)
    , nhi(nhi)
    , ep(ep)
    , info(info)
{
    // Register us in the registration_server's ID-lookup table,
    // replacing any existing entry with this ID.
    registry_record *old = srv->idhash.value(id);
    if (old != nullptr) {
        logger::debug() << "Replacing existing record for" << id;
        delete old;
    }
    srv->idhash[id] = this;
    srv->allrecords += this;

    logger::debug() << "Registering record for" << PeerId(id) << "at" << ep;

    // Register all our keywords in the registration_server's keyword table.
    regKeywords(true);

    // Set the record's timeout
    timer.start(TIMEOUT_SEC * 1000, this);
}

registry_record::~registry_record()
{
    logger::debug() << "~registry_record: deleting record for" << PeerId(id);

    assert(srv->idhash.value(id) == this);
    srv->idhash.remove(id);
    srv->allrecords.remove(this);

    regKeywords(false);
}

void
registry_record::regKeywords(bool insert)
{
    foreach (QString kw, RegInfo(info).keywords())
    {
        QSet<registry_record*> &set = srv->kwhash[kw];
        if (insert) {
            set.insert(this);
        } else {
            set.remove(this);
            if (set.isEmpty())
                srv->kwhash.remove(kw);
        }
    }
}

void
registry_record::timerEvent(QTimerEvent *)
{
    logger::debug() << "Timed out record for" << PeerId(id) << "at" << ep;

    // Our timeout expired - just silently delete this record.
    deleteLater();
}

} // internal namespace
} // routing namespace
} // uia namespace

//
// Main application entrypoint
//
int
main(int argc, char **argv)
{
    QDir homedir = QDir::home();
    QDir appdir;
    QString appdirname = ".regserver";
    homedir.mkdir(appdirname);
    appdir.setPath(homedir.path() + "/" + appdirname);

    // Send debugging output to a log file
    QString logname(appdir.path() + "/log");
    QString logbakname(appdir.path() + "/log-before-restart-on-"+QDateTime::currentDateTime().toString()+".bak");
    QFile::remove(logbakname);
    QFile::rename(logname, logbakname);
    logfile.setFileName(logname);
    if (!logfile.open(QFile::WriteOnly | QFile::Truncate))
        qWarning("Can't open log file '%s'", logname.toLocal8Bit().data());
    else
        qInstallMsgHandler(myMsgHandler);

    std::cout << "Writing to log " << logname.constData() << '\n';

    QCoreApplication app(argc, argv);
    registration_server regserv;
    return app.exec();
}
