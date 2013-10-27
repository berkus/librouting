//
// Part of Metta OS. Check http://metta.exquance.com for latest version.
//
// Copyright 2007 - 2013, Stanislav Karchebnyy <berkus@exquance.com>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//
#pragma once

#include <set>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <boost/signals2/signal.hpp>
#include "client_profile.h"
#include "routing_client.h"
#include "timer.h"
#include "peer_id.h"

namespace uia {
namespace routing {

class routing_receiver;

namespace internal {

constexpr uint16_t REGSERVER_DEFAULT_PORT = 9669;

// Control chunk magic value for the Netsteria registration protocol.
// The upper byte is zero to distinguish control packets from flow packets.
constexpr ssu::magic_t REG_MAGIC = 0x00524f55; // 'xROU'

constexpr uint32_t REG_REQUEST    = 0x100;   // Client-to-server request
constexpr uint32_t REG_RESPONSE   = 0x200;   // Server-to-client response
constexpr uint32_t REG_NOTIFY     = 0x300;   // Server-to-client async callback

constexpr uint32_t REG_INSERT1    = 0x00;    // Insert entry - preliminary request
constexpr uint32_t REG_INSERT2    = 0x01;    // Insert entry - authenticated request
constexpr uint32_t REG_LOOKUP     = 0x02;    // Lookup host by ID, optionally notify
constexpr uint32_t REG_SEARCH     = 0x03;    // Search entry by keyword
constexpr uint32_t REG_DELETE     = 0x04;    // Remove registration record, sent by client upon exit

/**
 * Implementation class talking to registration/rendezvous server.
 * It forwards its signals to routing_client instantiated by consumer, e.g. SSU host.
 */
class regserver_client : public client
{
public:
    enum class state : int {
        idle = 0,   // Unregistered and not doing anything
        resolve,    // Resolving rendezvous server's host name
        insert1,    // Sent Insert1 request, waiting response
        insert2,    // Sent Insert2 request, waiting response
        registered, // Successfully registered
    };

private:
    // Max time before rereg - 1 hr
    static const boost::posix_time::time_duration max_rereg;

    ssu::host* const host_;      // Pointer to our per-host state

    state state_;
    // DNS resolution info
    std::string srvname;    // DNS hostname or IP address of server
    uint16_t srvport;    // Port number of registration server
    boost::asio::ip::udp::resolver resolver_; 
    // int lookupid;       // QHostInfo lookupId for DNS resolution
    std::vector<ssu::endpoint> addrs; friend class uia::routing::routing_receiver; // Server addresses from resolution
    client_profile inf;        // Registration metadata

    // Registration process state
    byte_array idi;     // Initiator's identity (i.e., mine)
    byte_array ni;      // Initiator's nonce
    byte_array nhi;     // Initiator's hashed nonce
    byte_array chal;    // Responder's challenge from Insert1 reply
    byte_array key;     // Our encoded public key to send to server
    byte_array sig;     // Our signature to send in Insert2

    // Outstanding lookups and searches for which we're awaiting replies.
    std::unordered_set<ssu::peer_id> lookups;  // IDs we're doing lookups on
    std::unordered_set<ssu::peer_id> punches;  // Lookups with notify requests
    std::unordered_set<std::string> searches;  // Strings we're searching for

    // Retry state
    ssu::async::timer retry_timer_;   // Retransmission timer
    bool persist;       // True if we should never give up

    ssu::async::timer rereg_timer_;   // Counts lifetime of our reg entry

    // Error state
    std::string error_string_;

    // As the result of an error, disconnect and notify the client.
    void fail(const std::string &error);

public:
    regserver_client(ssu::host *h);
    ~regserver_client();

    // // Set the metadata to attach to our registration
    // inline RegInfo info() { return inf; }
    // inline void setInfo(const RegInfo &info) { inf = info; }

    // Attempt to register with the specified registration server.
    // We'll send a stateChanged() signal when it succeeds or fails.
    void register_at(const std::string &srvhost, uint16_t port = REGSERVER_DEFAULT_PORT);

    // Attempt to re-register with the same server previously indicated.
    void reregister();

    inline std::string server_name() { return srvname; }
    inline uint16_t server_port() { return srvport; }
    inline std::string name() const override { return server_name(); }

    inline std::string error_string() { return error_string_; }
    inline void set_error_string(const std::string &err) { error_string_ = err; }

    inline bool idle() { return state_ == state::idle; }
    inline bool registered() { return state_ == state::registered; }
    inline bool registering() { return !idle() && !registered(); }

    // A persistent RegClient will never give up trying to register,
    // and will try to re-register if its connection is lost.
    inline void set_persistent(bool persist) { this->persist = persist; }
    inline bool is_persistent() { return persist; }

    // Disconnect from our server or cancel the registration process,
    // and return immediately to the idle state.
    void disconnect();

    static std::string state_string(int state);

    void lookup(ssu::peer_id const& id, bool notify = false) override;
    void search(std::string const& text) override;

private:
    // Registration state machine
    void go_insert1();
    void send_insert1();
    void got_insert1_reply(byte_array_iwrap<flurry::iarchive>& is);

    void go_insert2();
    void send_insert2();
    void got_insert2_reply(byte_array_iwrap<flurry::iarchive>& is);

    void send_lookup(const ssu::peer_id& id, bool notify);
    void got_lookup_reply(byte_array_iwrap<flurry::iarchive>& is, bool isnotify);

    void send_search(const std::string &text);
    void got_search_reply(byte_array_iwrap<flurry::iarchive>& is);

    void send_delete();
    void got_delete_reply(byte_array_iwrap<flurry::iarchive>& is);

    void send(const byte_array &msg);

private:
    //==============
    // Handlers
    //==============
    void got_resolve_results(const boost::system::error_code& ec,
                             boost::asio::ip::udp::resolver::iterator ep_it);  // DNS lookup done
    void timeout(bool fail);        // Retry timer timeout
    void rereg_timeout();            // Reregister timeout
};

} // internal namespace
} // routing namespace
} // uia namespace
