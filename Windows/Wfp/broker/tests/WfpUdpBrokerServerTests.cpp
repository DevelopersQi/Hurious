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

    // A zero flow budget is invalid and must not publish a listener.
    assert(!server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress), true, false, 0));
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

    // A second Start while running must fail without replacing live endpoints.
    assert(!server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress), true, false, 16));
    const auto unchangedPorts = server.ListenerPorts();
    assert(unchangedPorts.ipv4 == ports.ipv4);
    assert(unchangedPorts.ipv6 == ports.ipv6);

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


void TestUdpBrokerStopUnderIngressLoadAndDualStackRestart() {
    const auto socksAddress = LoopbackSocksAddress();
    furious::wfp::broker::UdpBrokerServer server;

    // Start both listener families together: publishing only one family would
    // violate the endpoint contract used by the WFP service.
    assert(server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress), true, true, 32));
    const auto firstPorts = server.ListenerPorts();
    assert(firstPorts.ipv4 != 0);
    assert(firstPorts.ipv6 != 0);

    SOCKET client4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET client6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    assert(client4 != INVALID_SOCKET && client6 != INVALID_SOCKET);

    sockaddr_in target4{};
    target4.sin_family = AF_INET;
    target4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target4.sin_port = htons(firstPorts.ipv4);

    sockaddr_in6 target6{};
    target6.sin6_family = AF_INET6;
    target6.sin6_addr = in6addr_loopback;
    target6.sin6_port = htons(firstPorts.ipv6);

    std::atomic<bool> send{true};
    const char payload = 'u';
    std::thread producer([&]() {
        while (send.load()) {
            // The broker intentionally rejects packets without WFP redirect
            // metadata. This still exercises its ingress poll/receive path
            // while Stop races with sustained traffic.
            sendto(client4, &payload, sizeof(payload), 0,
                reinterpret_cast<const sockaddr*>(&target4), sizeof(target4));
            sendto(client6, &payload, sizeof(payload), 0,
                reinterpret_cast<const sockaddr*>(&target6), sizeof(target6));
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    server.Stop();
    send.store(false);
    producer.join();
    closesocket(client4);
    closesocket(client6);

    assert(!server.IsRunning());
    assert(server.ListenerPorts().ipv4 == 0);
    assert(server.ListenerPorts().ipv6 == 0);

    // Restart both families on the same object after the load-driven stop.
    assert(server.Start(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress), true, true, 16));
    const auto restartedPorts = server.ListenerPorts();
    assert(restartedPorts.ipv4 != 0);
    assert(restartedPorts.ipv6 != 0);

    SOCKET probe4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET probe6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    assert(probe4 != INVALID_SOCKET && probe6 != INVALID_SOCKET);
    target4.sin_port = htons(restartedPorts.ipv4);
    target6.sin6_port = htons(restartedPorts.ipv6);
    assert(sendto(probe4, &payload, sizeof(payload), 0,
        reinterpret_cast<const sockaddr*>(&target4), sizeof(target4)) ==
        sizeof(payload));
    assert(sendto(probe6, &payload, sizeof(payload), 0,
        reinterpret_cast<const sockaddr*>(&target6), sizeof(target6)) ==
        sizeof(payload));
    closesocket(probe4);
    closesocket(probe6);

    server.Stop();
    assert(server.ListenerPorts().ipv4 == 0);
    assert(server.ListenerPorts().ipv6 == 0);
}

int main() {
    TestUdpBrokerServerLifecycle();
    TestUdpBrokerConcurrentStartStopIsSerialized();
    TestUdpBrokerStopUnderIngressLoadAndDualStackRestart();
    return 0;
}
