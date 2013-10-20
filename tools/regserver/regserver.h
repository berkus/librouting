#pragma once

#include "byte_array.h"
#include "byte_array_wrap.h"
#include "link.h" // @todo move the link classes to comm::link
#include "timer.h" // @todo move ssu::async to async

namespace uia {
namespace routing {

class registration_server;

namespace internal {

// We maintain a registry_record for each registered client.
// For memory space efficiency, we keep info blocks in binary form
// and only break them out into a client_profile object when we need to.
// Private helper class for registration_server.
class registry_record
{
    registration_server * const srv;
    const byte_array id;
    const byte_array nhi;
    const ssu::endpoint ep;
    const byte_array info;
    ssu::async::timer timer_;

    registry_record(registration_server *srv, const byte_array &id, const byte_array &nhi,
        const ssu::endpoint &ep, const byte_array &info);
    ~registry_record();

    // Break the description into keywords,
    // and either insert or remove the keyword entries for this record.
    void regKeywords(bool insert);
};

} // internal namespace

class registration_server
{
    friend class registry_record;

    // The network code actually duplicates some from ssu::link, maybe this can be refactored.
    boost::asio::io_service io_service_;
    boost::asio::ip::udp::socket sock;
    boost::asio::streambuf received_buffer;
    ssu::endpoint received_from;
    std::string error_string_;

    // XX should timeout periodically
    byte_array secret;

    // Hash of insert challenge cookies and corresponding responses
    std::unordered_map<byte_array,byte_array> chalhash;

    // Hash table to look up records by ID
    std::unordered_map<byte_array,internal::registry_record*> idhash;

    // Hash table to look up records by case-insensitive keyword
    std::unordered_map<std::string, std::unordered_set<internal::registry_record*> > kwhash;

    // Set of all existing records, for empty searches
    std::unordered_set<internal::registry_record*> allrecords;

    void prepare_async_receive();

public:
    registration_server();

private:
    void udpDispatch(byte_array &msg, const ssu::endpoint &ep);
    void doInsert1(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint &ep);
    void doInsert2(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint &ep);
    void doLookup(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint &ep);
    void doSearch(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint &ep);
    void doDelete(byte_array_iwrap<flurry::iarchive>& is, const ssu::endpoint& ep);

    void replyInsert1(const ssu::endpoint &ep, const byte_array &idi, const byte_array &nhi);
    void replyLookup(internal::registry_record *reci, uint32_t replycode,
            const byte_array &idr, internal::registry_record *recr);
    byte_array calcCookie(const ssu::endpoint &ep, const byte_array &idi,
                const byte_array &nhi);
    internal::registry_record *findCaller(const ssu::endpoint &ep, const byte_array &idi,
                const byte_array &nhi);

private:
    void udp_ready_read(const boost::system::error_code& error, size_t bytes_transferred);
    bool send(const ssu::endpoint& ep, byte_array const& msg);
};

} // routing namespace
} // uia namespace