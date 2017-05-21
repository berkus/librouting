//
// Part of Metta OS. Check https://metta.systems for latest version.
//
// Copyright 2007 - 2017, Stanislav Karchebnyy <berkus@metta.systems>
//
// Distributed under the Boost Software License, Version 1.0.
// (See file LICENSE_1_0.txt or a copy at http://www.boost.org/LICENSE_1_0.txt)
//

template <int Bits = 160>
class kademlia_id
{
    boost::array<char, (Bits+7)/8> value;
};

// Kademlia XOR distance metric.
template <int Bits = 160>
class distance_metric
{
    kademlia_id<Bits> operator ()(kademlia_id<Bits> id1, kademlia_id<Bits> id2)
    {
    }
};

template <int Bits = 160>
class k_buckets
{
    boost::array<std::deque<kademlia_node>, Bits> buckets;
};

class kademlia_message
{
    kademlia_id target;
    kademlia_id source;
    kademlia_id nonce;
};

enum class message_type
{
    PING_REQUEST,
    PING_REPLY_REQUEST,
    PING_REPLY,
    FIND_NODE,
    REPLY_NODE,
    FIND_VALUE,
    REPLY_VALUE,
    STORE_RPC
};
