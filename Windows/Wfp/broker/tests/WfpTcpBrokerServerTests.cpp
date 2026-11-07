#include "../WfpTcpBrokerServer.h"

#include <cassert>
#include <cstdint>

void TestBrokerServerLifecycle() {
    sockaddr_in socksAddress{};
    socksAddress.sin_family = AF_INET;
    socksAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socksAddress.sin_port = htons(10808);

    furious::wfp::broker::TcpBrokerServer server;
    assert(server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress),
        true,
        false,
        2,
        8));
    assert(server.IsRunning());
    assert(server.ProcessId() != 0);
    assert(server.ListenerPorts().ipv4 != 0);
    assert(server.ListenerPorts().ipv6 == 0);
    assert(server.IsConfiguredFor(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress)));

    sockaddr_in differentSocksAddress = socksAddress;
    differentSocksAddress.sin_port = htons(10809);
    assert(!server.IsConfiguredFor(
        reinterpret_cast<const sockaddr*>(&differentSocksAddress),
        sizeof(differentSocksAddress)));

    server.Stop();
    server.Stop();
    assert(!server.IsRunning());
    assert(server.ListenerPorts().ipv4 == 0);

    assert(server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress),
        true,
        false,
        1,
        4));
    assert(server.IsRunning());
    server.Stop();
    return 0;
}
