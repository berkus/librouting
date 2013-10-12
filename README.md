P2P routing
===========

Routing layer exploiting different routing methods for higher availability p2p
networks configuration.

* Social routing
* Identity Hash routing
* Compact routing

The reason for this library is to provide single interface for multitude of routing
strategies. Ideally the library would support combination of different strategies at the same
time for better reachability.

Every client can incorporate the routing mechanisms supported by the library and provide it
to other clients, making it truly a peer to peer network.

Additional mechanisms that may be used for discovering the nodes:
* Bonjour/Zeroconf
* Netsukuku
* DHT
* Dedicated tracking servers

See also:
* CAN routing methods - http://berkeley.intel-research.net/sylvia/cans.pdf
* Scatter - http://sigops.org/sosp/sosp11/current/2011-Cascais/02-glendenning-online.pdf

Directory Structure
===================

lib         Core routing implementation library (librouting)
regserver   Lightweight standalone registration server for NAT traversal
            This server may be integrated into every host running SSU.


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/berkus/librouting/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

