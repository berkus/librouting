template <int Bits = 160>
class kademlia_id
{
    boost::array<char, (Bits+7)/8> value;
};

class kademlia_message
{
    kademlia_id target;
    kademlia_id source;
    kademlia_id nonce;
};
