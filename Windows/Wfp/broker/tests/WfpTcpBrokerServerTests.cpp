#include "../WfpTcpBrokerServer.h"

#include <cassert>
#include <chrono>
#include <cstdint>
#include <vector>
#include <thread>

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
        true,
        2,
        8));
    assert(server.IsRunning());
    assert(server.ProcessId() != 0);
    const auto initialPorts = server.ListenerPorts();
    assert(initialPorts.ipv4 != 0);
    if (initialPorts.ipv6 != 0) {
        SOCKET ipv6Client = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        assert(ipv6Client != INVALID_SOCKET);
        sockaddr_in6 ipv6Target{};
        ipv6Target.sin6_family = AF_INET6;
        ipv6Target.sin6_addr = in6addr_loopback;
        ipv6Target.sin6_port = htons(initialPorts.ipv6);
        assert(connect(ipv6Client,
            reinterpret_cast<const sockaddr*>(&ipv6Target),
            sizeof(ipv6Target)) == 0);
        closesocket(ipv6Client);
    }
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
    assert(server.ListenerPorts().ipv6 == 0);

    assert(server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress),
        true,
        false,
        1,
        4));
    assert(server.IsRunning());
    server.Stop();
}


void TestBrokerConcurrentStartStopIsSerialized() {
    sockaddr_in socksAddress{};
    socksAddress.sin_family = AF_INET;
    socksAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socksAddress.sin_port = htons(10808);

    furious::wfp::broker::TcpBrokerServer server;
    std::thread starter([&]() {
        for (size_t index = 0; index < 12; ++index) {
            if (server.Start(
                    reinterpret_cast<const sockaddr*>(&socksAddress),
                    sizeof(socksAddress), true, false, 1, 8)) {
                server.Stop();
            }
        }
    });
    std::thread stopper([&]() {
        for (size_t index = 0; index < 24; ++index) {
            server.Stop();
        }
    });

    starter.join();
    stopper.join();
    server.Stop();
    assert(!server.IsRunning());
    assert(server.ListenerPorts().ipv4 == 0);
    assert(server.ListenerPorts().ipv6 == 0);
}

void TestBrokerStopsWhileAcceptingConnections() {
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
        64));

    const auto ports = server.ListenerPorts();
    assert(ports.ipv4 != 0);

    std::vector<SOCKET> clients;
    for (size_t index = 0; index < 32; ++index) {
        SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        assert(client != INVALID_SOCKET);
        sockaddr_in target{};
        target.sin_family = AF_INET;
        target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        target.sin_port = htons(ports.ipv4);
        if (connect(client, reinterpret_cast<const sockaddr*>(&target),
                sizeof(target)) == SOCKET_ERROR) {
            closesocket(client);
            break;
        }
        clients.push_back(client);
    }

    const auto started = std::chrono::steady_clock::now();
    server.Stop();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    assert(elapsed < std::chrono::seconds(5));

    for (SOCKET client : clients) {
        closesocket(client);
    }
    assert(!server.IsRunning());
    assert(server.ListenerPorts().ipv4 == 0);
}
