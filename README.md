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

Additional mechanisms may be used for discovering the [nodes](http://en.wikipedia.org/wiki/Bootstrapping_node):
* Bonjour/Zeroconf
* Netsukuku
* DHT
* DNS
* Dedicated tracking servers IP

See also:
* CAN routing methods - in doc/cans.pdf
* Scatter - doc/02-glendenning-online.pdf

Directory Structure
===================

lib         Core routing implementation library (librouting)
regserver   Lightweight standalone registration server for NAT traversal
            This server may be integrated into every host running SSS.


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/berkus/librouting/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

