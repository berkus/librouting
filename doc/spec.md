Routing Protocol
================

## 1 Introduction

Routing protocol provides means to find path to specified network node without knowing its address beforehand. It is based on a number of known protocols to provide a distributed, redundant network of information about where each given node resides.



Packet types

PING
- check availability of a node by ID
STORE
- store metadata with node ID
FIND_NODE
- find coordinates of node by ID
FIND_VALUE
- find coordinates of node having piece of meta
FORWARD_ANONYMOUSLY
- send a packet to target ID using DHT neighbours
- it's only possible to answer to such packets by using FORWARD_ANONYMOUSLY in response

Some more types needed for routing? Like searching for user by info, or looking up your passport profile vault location.



