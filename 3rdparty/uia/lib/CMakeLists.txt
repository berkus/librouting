set(simulator_SOURCES
    simulation/sim_connection.cpp
    simulation/sim_host.cpp
    simulation/sim_socket.cpp
    simulation/sim_packet.cpp
    simulation/sim_timer_engine.cpp
    simulation/simulator.cpp)

set(platform_SOURCES)
if (UNIX)
    list(APPEND platform_SOURCES
        comm/platform-unix.cpp)
endif()
if (WIN32)
    list(APPEND platform_SOURCES
        comm/platform-win.cpp)
endif()

set(comm_SOURCES
    comm/socket.cpp
    comm/udp_socket.cpp
    comm/socket_endpoint.cpp
    comm/packet_receiver.cpp
    comm/socket_host_state.cpp
    )

set(kex_SOURCES
    negotiation/initiator.cpp
    negotiation/responder.cpp
    negotiation/kex_host_state.cpp
    )

add_library(uia STATIC
    host.cpp
    peer_identity.cpp
    peer.cpp
    message_receiver.cpp
    channels/socket_channel.cpp
    channels/channel_host_state.cpp
    timer.cpp
    asio_host_state.cpp
    ${simulator_SOURCES}
    ${comm_SOURCES}
    ${platform_SOURCES}
    ${kex_SOURCES})
