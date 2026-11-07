#include "../WfpUdpBrokerServer.h"

#include <cassert>
#include <chrono>
#include <thread>

namespace {
sockaddr_in LoopbackSocksAddress() {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(10808);
    return address;
}
}

void TestUdpBrokerServerLifecycle() {
    const auto socksAddress = LoopbackSocksAddress();
    furious::wfp::broker::UdpBrokerServer server;

    // Reject a non-loopback SOCKS endpoint after Winsock/listener setup, then
    // prove that the same server object can start cleanly on a valid endpoint.
    auto invalidSocksAddress = socksAddress;
    invalidSocksAddress.sin_addr.s_addr = htonl(INADDR_ANY);
    assert(!server.Start(
        reinterpret_cast<const sockaddr*>(&invalidSocksAddress),
        sizeof(invalidSocksAddress), true, false, 8));
    assert(!server.IsRunning());
    assert(server.ListenerPorts().ipv4 == 0);
    assert(server.ListenerPorts().ipv6 == 0);

    assert(server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress), true, false, 8));
    assert(server.IsRunning());
    const auto ports = server.ListenerPorts();
    assert(ports.ipv4 != 0);
    assert(ports.ipv6 == 0);

    // The listener is loopback-only and bound to an ephemeral UDP port.
    SOCKET client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(client != INVALID_SOCKET);
    sockaddr_in target{};
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons(ports.ipv4);
    const char probe = 'x';
    assert(sendto(client, &probe, sizeof(probe), 0,
        reinterpret_cast<const sockaddr*>(&target), sizeof(target)) == sizeof(probe));
    closesocket(client);

    server.Stop();
    server.Stop();
    assert(!server.IsRunning());
    assert(server.ListenerPorts().ipv4 == 0);
    assert(server.ListenerPorts().ipv6 == 0);

    // A failed startup must leave no published listener state and must permit
    // a subsequent clean start on the same server instance.
    assert(server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress), true, false, 4));
    assert(server.IsRunning());
    server.Stop();
}

void TestUdpBrokerConcurrentStartStopIsSerialized() {
    const auto socksAddress = LoopbackSocksAddress();
    furious::wfp::broker::UdpBrokerServer server;

    std::thread starter([&]() {
        for (size_t index = 0; index < 8; ++index) {
            if (server.Start(
                    reinterpret_cast<const sockaddr*>(&socksAddress),
                    sizeof(socksAddress), true, false, 4)) {
                server.Stop();
            }
        }
    });
    std::thread stopper([&]() {
        for (size_t index = 0; index < 16; ++index) server.Stop();
    });

    starter.join();
    stopper.join();
    server.Stop();
    assert(!server.IsRunning());
    assert(server.ListenerPorts().ipv4 == 0);
    assert(server.ListenerPorts().ipv6 == 0);
}

int main() {
    TestUdpBrokerServerLifecycle();
    TestUdpBrokerConcurrentStartStopIsSerialized();
    return 0;
}
