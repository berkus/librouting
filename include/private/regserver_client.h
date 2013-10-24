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
#include <boost/signals2/signal.hpp>
#include "client_profile.h"
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
class regserver_client
{
public:
    enum class state {
        idle = 0,   // Unregistered and not doing anything
        resolve,    // Resolving rendezvous server's host name
        insert1,    // Sent Insert1 request, waiting response
        insert2,    // Sent Insert2 request, waiting response
        registered, // Successfully registered
    };

private:
    // Max time before rereg - 1 hr
    static const int64_t maxRereg = (int64_t)60*60*1000000;

    ssu::host* const h;      // Pointer to our per-host state

    state state_;
    // DNS resolution info
    std::string srvname;    // DNS hostname or IP address of server
    uint16_t srvport;    // Port number of registration server
    // int lookupid;       // QHostInfo lookupId for DNS resolution
    std::list<ssu::endpoint> addrs; friend class uia::routing::routing_receiver; // Server addresses from resolution
    client_profile inf;        // Registration metadata

    // Registration process state
    byte_array idi;     // Initiator's identity (i.e., mine)
    byte_array ni;      // Initiator's nonce
    byte_array nhi;     // Initiator's hashed nonce
    byte_array chal;    // Responder's challenge from Insert1 reply
    byte_array key;     // Our encoded public key to send to server
    byte_array sig;     // Our signature to send in Insert2

    // Outstanding lookups and searches for which we're awaiting replies.
    std::set<ssu::peer_id> lookups;  // IDs we're doing lookups on
    std::set<ssu::peer_id> punches;  // Lookups with notify requests
    std::set<std::string> searches;  // Strings we're searching for

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

    //=============
    // Signals
    //=============

    typedef boost::signals2::signal<void(int)> state_change_signal;
    /**
     * Indicate registration state change to the client.
     * @param state State of the regserver connection (from enum State).
     */
    state_change_signal on_state_changed;

private:
    // Registration state machine
    void goInsert1();
    void sendInsert1();
    void gotInsert1Reply(byte_array_iwrap<flurry::iarchive>& is);

    void goInsert2();
    void sendInsert2();
    void gotInsert2Reply(byte_array_iwrap<flurry::iarchive>& is);

    void sendLookup(const ssu::peer_id& id, bool notify);
    void gotLookupReply(byte_array_iwrap<flurry::iarchive>& is, bool isnotify);

    void sendSearch(const std::string &text);
    void gotSearchReply(byte_array_iwrap<flurry::iarchive>& is);

    void sendDelete();
    void gotDeleteReply(byte_array_iwrap<flurry::iarchive>& is);

    void send(const byte_array &msg);


private:
    //==============
    // Handlers
    //==============
    void resolveDone(const boost::system::error_code& ec,
    boost::asio::ip::udp::resolver::iterator ep_it);  // DNS lookup done
    void timeout(bool fail);        // Retry timer timeout
    void reregTimeout();            // Reregister timeout
};

} // internal namespace
} // routing namespace
} // uia namespace
