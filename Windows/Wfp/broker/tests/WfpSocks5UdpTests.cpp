#include "../WfpSocks5Udp.h"
#include "../WfpSocks5UdpControl.h"
#include "../WfpSocks5UdpAssociation.h"
#include "../WfpSocks5UdpAssociationManager.h"
#include "../WfpSocks5UdpAssociationClient.h"
#include "../WfpSocks5UdpSocket.h"
#include "../WfpSocks5UdpRelayTransport.h"
#include "../WfpSocks5UdpRedirectRecord.h"
#include "../WfpUdpFlowManager.h"
#include "../WfpUdpFlowRelayRegistry.h"
#include "../../include/WfpRedirectProtocol.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <vector>
#include <thread>

using namespace furious::wfp::broker;

namespace {
bool ReceiveExactSocket(SOCKET socket, std::uint8_t* output, std::size_t length);
bool SendAllSocket(SOCKET socket, const std::uint8_t* input, std::size_t length);

Socks5UdpEndpoint V4(std::uint8_t a, std::uint8_t b,
                     std::uint8_t c, std::uint8_t d,
                     std::uint16_t port = 0) {
    Socks5UdpEndpoint endpoint{};
    endpoint.family = Socks5UdpEndpointFamily::Ipv4;
    endpoint.address[0] = a;
    endpoint.address[1] = b;
    endpoint.address[2] = c;
    endpoint.address[3] = d;
    endpoint.port = port;
    return endpoint;
}

void TestDatagramRoundTrips() {
    const std::array<std::uint8_t, 4> ipv4{192, 0, 2, 10};
    const std::array<std::uint8_t, 16> ipv6{
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1
    };
    const std::array<std::uint8_t, 7> domain{
        'e', 'x', 'a', 'm', 'p', 'l', 'e'
    };
    const std::array<std::uint8_t, 3> payload{0xAA, 0xBB, 0xCC};
    std::vector<std::uint8_t> datagram;
    Socks5UdpDatagramView view{};

    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        ipv4.data(), ipv4.size(), 5353, payload.data(), payload.size(),
        datagram) == Socks5UdpBuildResult::Valid);
    assert(ParseSocks5UdpDatagram(datagram.data(), datagram.size(), view) ==
        Socks5UdpParseResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Ipv4);
    assert(view.addressLength == ipv4.size() && view.port == 5353);
    assert(view.payloadLength == payload.size());
    assert(view.payload[0] == payload[0] && view.payload[2] == payload[2]);

    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv6,
        ipv6.data(), ipv6.size(), 443, payload.data(), payload.size(),
        datagram) == Socks5UdpBuildResult::Valid);
    assert(ParseSocks5UdpDatagram(datagram.data(), datagram.size(), view) ==
        Socks5UdpParseResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Ipv6);
    assert(view.addressLength == ipv6.size() && view.port == 443);

    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Domain,
        domain.data(), domain.size(), 53, payload.data(), payload.size(),
        datagram) == Socks5UdpBuildResult::Valid);
    assert(ParseSocks5UdpDatagram(datagram.data(), datagram.size(), view) ==
        Socks5UdpParseResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Domain);
    assert(view.addressLength == domain.size() && view.port == 53);
}

void TestDatagramRejectsMalformedInput() {
    Socks5UdpDatagramView view{};
    const std::array<std::uint8_t, 3> shortHeader{0, 0, 0};
    assert(ParseSocks5UdpDatagram(shortHeader.data(), shortHeader.size(), view) ==
        Socks5UdpParseResult::Truncated);
    assert(ParseSocks5UdpDatagram(nullptr, 0, view) ==
        Socks5UdpParseResult::NullDatagram);

    const std::array<std::uint8_t, 10> badReserved{
        1, 0, 0, 1, 192, 0, 2, 1, 0x14, 0xE9
    };
    assert(ParseSocks5UdpDatagram(badReserved.data(), badReserved.size(), view) ==
        Socks5UdpParseResult::InvalidReservedField);

    auto fragmented = badReserved;
    fragmented[0] = 0;
    fragmented[2] = 1;
    assert(ParseSocks5UdpDatagram(fragmented.data(), fragmented.size(), view) ==
        Socks5UdpParseResult::FragmentationUnsupported);

    const std::array<std::uint8_t, 4> unknownType{0, 0, 0, 5};
    assert(ParseSocks5UdpDatagram(unknownType.data(), unknownType.size(), view) ==
        Socks5UdpParseResult::UnsupportedAddressType);

    const std::array<std::uint8_t, 5> emptyDomain{0, 0, 0, 3, 0};
    assert(ParseSocks5UdpDatagram(emptyDomain.data(), emptyDomain.size(), view) ==
        Socks5UdpParseResult::EmptyDomain);

    const std::array<std::uint8_t, 10> zeroPort{
        0, 0, 0, 1, 192, 0, 2, 1, 0, 0
    };
    assert(ParseSocks5UdpDatagram(zeroPort.data(), zeroPort.size(), view) ==
        Socks5UdpParseResult::InvalidPort);

    const std::array<std::uint8_t, 4> address{192, 0, 2, 1};
    std::vector<std::uint8_t> output{1, 2, 3};
    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        address.data(), address.size(), 53, nullptr, 1, output) ==
        Socks5UdpBuildResult::NullPayload);
    assert(output.empty());
    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        address.data(), address.size(), 53, nullptr, 0, output, 8) ==
        Socks5UdpBuildResult::DatagramTooLarge);
    assert(output.empty());
}

void TestAssociateControlMessages() {
    const std::array<std::uint8_t, 10> request{
        0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1, 0, 0
    };
    Socks5UdpAssociateRequestView requestView{};
    assert(ParseSocks5UdpAssociateRequest(
        request.data(), request.size(), requestView) ==
        Socks5UdpAssociateRequestResult::Valid);
    assert(requestView.addressType == Socks5UdpAddressType::Ipv4);
    assert(requestView.addressLength == 4 && requestView.port == 0);

    auto badCommand = request;
    badCommand[1] = 1;
    assert(ParseSocks5UdpAssociateRequest(
        badCommand.data(), badCommand.size(), requestView) ==
        Socks5UdpAssociateRequestResult::UnsupportedCommand);

    const std::array<std::uint8_t, 4> address{127, 0, 0, 1};
    std::vector<std::uint8_t> reply;
    assert(BuildSocks5UdpAssociateReply(Socks5UdpAddressType::Ipv4,
        address.data(), address.size(), 41000, reply) ==
        Socks5UdpBuildResult::Valid);
    Socks5UdpAssociateReplyView replyView{};
    assert(ParseSocks5UdpAssociateReply(
        reply.data(), reply.size(), replyView) ==
        Socks5UdpAssociateReplyResult::Valid);
    assert(replyView.port == 41000 && replyView.addressLength == 4);

    reply.back() = 0;
    reply[reply.size() - 2] = 0;
    assert(ParseSocks5UdpAssociateReply(
        reply.data(), reply.size(), replyView) ==
        Socks5UdpAssociateReplyResult::InvalidPort);
}

void TestRedirectContextDecodeRequiresValidUdpMetadata() {
    FURIOUS_WFP_REDIRECT_CONTEXT context{};
    context.Magic = FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC;
    context.Size = sizeof(context);
    context.AbiVersion = FURIOUS_WFP_REDIRECT_ABI_VERSION;
    context.AddressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V4;
    context.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_UDP;
    context.OriginalPortNetworkOrder = 0x5000;
    context.OriginalAddress[0] = 192;
    context.OriginalAddress[1] = 0;
    context.OriginalAddress[2] = 2;
    context.OriginalAddress[3] = 1;
    context.OriginalProcessId = 1234;
    context.PolicyGeneration = 9;

    std::vector<std::uint8_t> bytes(sizeof(context));
    std::memcpy(bytes.data(), &context, sizeof(context));
    FURIOUS_WFP_REDIRECT_CONTEXT decoded{};
    assert(DecodeWfpUdpRedirectContext(bytes, decoded) ==
        WfpUdpRedirectContextDecodeResult::Decoded);
    assert(decoded.Protocol == FURIOUS_WFP_REDIRECT_PROTOCOL_UDP);

    context.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_TCP;
    std::memcpy(bytes.data(), &context, sizeof(context));
    assert(DecodeWfpUdpRedirectContext(bytes, decoded) ==
        WfpUdpRedirectContextDecodeResult::NotUdp);
    assert(decoded.Magic == 0);

    context.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_UDP;
    context.Reserved[0] = 1;
    std::memcpy(bytes.data(), &context, sizeof(context));
    assert(DecodeWfpUdpRedirectContext(bytes, decoded) ==
        WfpUdpRedirectContextDecodeResult::InvalidContext);
    assert(decoded.Magic == 0);

    bytes.pop_back();
    assert(DecodeWfpUdpRedirectContext(bytes, decoded) ==
        WfpUdpRedirectContextDecodeResult::InvalidSize);
}

FURIOUS_WFP_REDIRECT_CONTEXT MakeUdpRedirectContext(
    FURIOUS_WFP_U32 processId, FURIOUS_WFP_U32 priority = 1) {
    FURIOUS_WFP_REDIRECT_CONTEXT context{};
    context.Magic = FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC;
    context.Size = sizeof(context);
    context.AbiVersion = FURIOUS_WFP_REDIRECT_ABI_VERSION;
    context.AddressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V4;
    context.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_UDP;
    context.OriginalPortNetworkOrder = htons(443);
    context.OriginalAddress[0] = 198;
    context.OriginalAddress[1] = 51;
    context.OriginalAddress[2] = 100;
    context.OriginalAddress[3] = 8;
    context.OriginalProcessId = processId;
    context.RulePriority = priority;
    context.PolicyGeneration = 12;
    return context;
}

sockaddr_in FlowSource(std::uint16_t port) {
    sockaddr_in source{};
    source.sin_family = AF_INET;
    source.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    source.sin_port = htons(port);
    return source;
}

void TestUdpFlowManagerIdentityLimitsAndExpiry() {
    using Clock = WfpUdpFlowManager::Clock;
    const auto now = Clock::now();
    WfpUdpFlowManager manager(2, 1, std::chrono::seconds(10));
    const auto context = MakeUdpRedirectContext(1001);
    const std::vector<std::uint8_t> record{0x10, 0x20, 0x30};
    auto source1 = FlowSource(50001);
    std::uint64_t flow1 = 0;

    assert(manager.RegisterFirstDatagram(
        reinterpret_cast<const sockaddr*>(&source1), sizeof(source1),
        context, record, now, flow1) == WfpUdpFlowCreateResult::Created);
    assert(flow1 != 0);
    std::uint64_t existingId = 0;
    assert(manager.RegisterFirstDatagram(
        reinterpret_cast<const sockaddr*>(&source1), sizeof(source1),
        context, record, now + std::chrono::seconds(1), existingId) ==
        WfpUdpFlowCreateResult::ExistingFlow);
    assert(existingId == flow1);

    auto conflictingContext = context;
    conflictingContext.RulePriority = 2;
    std::uint64_t conflictId = 0;
    assert(manager.RegisterFirstDatagram(
        reinterpret_cast<const sockaddr*>(&source1), sizeof(source1),
        conflictingContext, record, now + std::chrono::seconds(2), conflictId) ==
        WfpUdpFlowCreateResult::SourceEndpointConflict);

    WfpUdpFlowSnapshot snapshot{};
    assert(manager.GetSnapshot(flow1, snapshot));
    assert(snapshot.id == flow1);
    assert(snapshot.redirectContext.OriginalProcessId == 1001);
    assert(snapshot.redirectRecord == record);

    auto source2 = FlowSource(50002);
    std::uint64_t flow2 = 0;
    assert(manager.RegisterFirstDatagram(
        reinterpret_cast<const sockaddr*>(&source2), sizeof(source2),
        context, record, now, flow2) ==
        WfpUdpFlowCreateResult::PerProcessLimitReached);

    auto context2 = MakeUdpRedirectContext(1002);
    assert(manager.RegisterFirstDatagram(
        reinterpret_cast<const sockaddr*>(&source2), sizeof(source2),
        context2, record, now, flow2) == WfpUdpFlowCreateResult::Created);
    assert(manager.ActiveCount() == 2);

    auto source3 = FlowSource(50003);
    auto context3 = MakeUdpRedirectContext(1003);
    std::uint64_t flow3 = 0;
    assert(manager.RegisterFirstDatagram(
        reinterpret_cast<const sockaddr*>(&source3), sizeof(source3),
        context3, record, now, flow3) ==
        WfpUdpFlowCreateResult::FlowLimitReached);

    std::uint64_t touchedId = 0;
    assert(manager.Touch(reinterpret_cast<const sockaddr*>(&source1),
        sizeof(source1), now + std::chrono::seconds(2), touchedId) ==
        WfpUdpFlowTouchResult::Found);
    assert(touchedId == flow1);
    assert(manager.IsActive(flow1, now + std::chrono::seconds(9)));
    assert(!manager.IsActive(flow1, now + std::chrono::seconds(12)));

    std::vector<std::uint64_t> expired;
    assert(manager.SweepExpired(now + std::chrono::seconds(12), expired) == 2);
    assert(expired.size() == 2);
    assert(manager.Remove(flow1));
    assert(manager.Remove(flow2));
    assert(manager.ActiveCount() == 0);

    auto invalidContext = MakeUdpRedirectContext(1004);
    invalidContext.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_TCP;
    assert(manager.RegisterFirstDatagram(
        reinterpret_cast<const sockaddr*>(&source3), sizeof(source3),
        invalidContext, record, now, flow3) ==
        WfpUdpFlowCreateResult::InvalidContext);
}

void TestUdpFlowRegistryForwardsFirstDatagramToSocksRelay() {
    SOCKET tcpListener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKET udpRelay = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(tcpListener != INVALID_SOCKET && udpRelay != INVALID_SOCKET);

    sockaddr_in socksAddress{};
    socksAddress.sin_family = AF_INET;
    socksAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(tcpListener, reinterpret_cast<const sockaddr*>(&socksAddress),
        static_cast<int>(sizeof(socksAddress))) == 0);
    assert(listen(tcpListener, 1) == 0);
    int socksLength = static_cast<int>(sizeof(socksAddress));
    assert(getsockname(tcpListener, reinterpret_cast<sockaddr*>(&socksAddress),
        &socksLength) == 0);

    sockaddr_in relayAddress{};
    relayAddress.sin_family = AF_INET;
    relayAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(udpRelay, reinterpret_cast<const sockaddr*>(&relayAddress),
        static_cast<int>(sizeof(relayAddress))) == 0);
    int relayLength = static_cast<int>(sizeof(relayAddress));
    assert(getsockname(udpRelay, reinterpret_cast<sockaddr*>(&relayAddress),
        &relayLength) == 0);

    std::atomic<bool> relayVerified{false};
    std::atomic<bool> serverFinished{false};
    std::thread fakeSocksServer([&]() {
        SOCKET peer = INVALID_SOCKET;
        do {
            fd_set tcpReadable;
            FD_ZERO(&tcpReadable);
            FD_SET(tcpListener, &tcpReadable);
            timeval acceptTimeout{3, 0};
            if (select(0, &tcpReadable, nullptr, nullptr, &acceptTimeout) <= 0) break;
            peer = accept(tcpListener, nullptr, nullptr);
            if (peer == INVALID_SOCKET) break;

            std::array<std::uint8_t, 3> greeting{};
            if (!ReceiveExactSocket(peer, greeting.data(), greeting.size()) ||
                greeting != std::array<std::uint8_t, 3>{5, 1, 0}) break;
            const std::array<std::uint8_t, 2> methodReply{5, 0};
            if (!SendAllSocket(peer, methodReply.data(), methodReply.size())) break;

            std::array<std::uint8_t, 10> associateRequest{};
            if (!ReceiveExactSocket(peer, associateRequest.data(),
                    associateRequest.size()) ||
                associateRequest[0] != 5 || associateRequest[1] != 3 ||
                associateRequest[2] != 0) break;

            const auto relayPort = ntohs(relayAddress.sin_port);
            const std::array<std::uint8_t, 10> associateReply{
                5, 0, 0, 1, 127, 0, 0, 1,
                static_cast<std::uint8_t>(relayPort >> 8),
                static_cast<std::uint8_t>(relayPort & 0xFF)
            };
            if (!SendAllSocket(peer, associateReply.data(), associateReply.size())) break;

            fd_set udpReadable;
            FD_ZERO(&udpReadable);
            FD_SET(udpRelay, &udpReadable);
            timeval udpTimeout{3, 0};
            if (select(0, &udpReadable, nullptr, nullptr, &udpTimeout) <= 0) break;

            std::array<std::uint8_t, 2048> datagram{};
            sockaddr_in sender{};
            int senderLength = static_cast<int>(sizeof(sender));
            const int received = recvfrom(udpRelay,
                reinterpret_cast<char*>(datagram.data()),
                static_cast<int>(datagram.size()), 0,
                reinterpret_cast<sockaddr*>(&sender), &senderLength);
            if (received <= 0) break;

            Socks5UdpDatagramView view{};
            const std::array<std::uint8_t, 4> expectedAddress{198, 51, 100, 8};
            const std::array<std::uint8_t, 4> expectedPayload{'p', 'i', 'n', 'g'};
            if (ParseSocks5UdpDatagram(datagram.data(),
                    static_cast<std::size_t>(received), view) ==
                    Socks5UdpParseResult::Valid &&
                view.addressType == Socks5UdpAddressType::Ipv4 &&
                view.addressLength == expectedAddress.size() &&
                std::memcmp(view.address, expectedAddress.data(),
                    expectedAddress.size()) == 0 &&
                view.port == 443 &&
                view.payloadLength == expectedPayload.size() &&
                std::memcmp(view.payload, expectedPayload.data(),
                    expectedPayload.size()) == 0) {
                relayVerified.store(true);
            }
        } while (false);

        if (peer != INVALID_SOCKET) closesocket(peer);
        serverFinished.store(true);
    });

    furious::wfp::broker::WfpUdpFlowRelayRegistry registry(4, 2,
        std::chrono::seconds(10));
    assert(registry.Configure(reinterpret_cast<const sockaddr*>(&socksAddress),
        static_cast<int>(sizeof(socksAddress)), 3000));

    WfpUdpReceivedMessage message{};
    auto source = FlowSource(50050);
    source.sin_addr.s_addr = htonl(0xC000020A); // 192.0.2.10
    std::memcpy(&message.sourceAddress, &source, sizeof(source));
    message.sourceAddressLength = static_cast<int>(sizeof(source));
    message.payloadLength = 4;
    message.redirectRecord = {0x11, 0x22, 0x33};
    const auto redirectContext = MakeUdpRedirectContext(1001);
    message.redirectContext.resize(sizeof(redirectContext));
    std::memcpy(message.redirectContext.data(), &redirectContext,
        sizeof(redirectContext));
    const std::array<std::uint8_t, 4> payload{'p', 'i', 'n', 'g'};

    std::uint64_t flowId = 0;
    const auto startResult = registry.ProcessClientDatagram(
        message, payload.data(), WfpUdpFlowRelayRegistry::Clock::now(),
        &flowId);
    assert(startResult == WfpUdpFlowRelayRegistryResult::Pending);
    assert(flowId != 0);

    auto handshakeResult = WfpUdpFlowRelayRegistryResult::Pending;
    const auto handshakeDeadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(2);
    while (handshakeResult == WfpUdpFlowRelayRegistryResult::Pending &&
           std::chrono::steady_clock::now() < handshakeDeadline) {
        std::vector<WfpUdpRelaySocket> relays;
        if (!registry.GetRelaySockets(relays)) break;
        const auto relay = std::find_if(relays.begin(), relays.end(),
            [flowId](const WfpUdpRelaySocket& item) {
                return item.flowId == flowId;
            });
        if (relay == relays.end()) break;

        WSAPOLLFD descriptor{};
        descriptor.fd = relay->controlSocket;
        if (relay->wantsRead) descriptor.events |= POLLRDNORM;
        if (relay->wantsWrite) descriptor.events |= POLLWRNORM;
        const int ready = WSAPoll(&descriptor, 1, 100);
        if (ready == SOCKET_ERROR) break;
        const bool readable = ready > 0 && (descriptor.revents &
            (POLLRDNORM | POLLERR | POLLHUP)) != 0;
        const bool writable = ready > 0 && (descriptor.revents &
            (POLLWRNORM | POLLERR | POLLHUP)) != 0;
        handshakeResult = registry.AdvancePendingFlow(flowId, readable, writable);
        if (handshakeResult != WfpUdpFlowRelayRegistryResult::Pending &&
            handshakeResult != WfpUdpFlowRelayRegistryResult::Ready) break;
    }

    const bool handshakeReady =
        handshakeResult == WfpUdpFlowRelayRegistryResult::Ready;
    const auto relayDeadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(1);
    while (!relayVerified.load() && !serverFinished.load() &&
           std::chrono::steady_clock::now() < relayDeadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    const bool datagramForwarded = relayVerified.load();

    registry.CloseAll();
    fakeSocksServer.join();
    closesocket(tcpListener);
    closesocket(udpRelay);

    assert(handshakeReady);
    assert(datagramForwarded);
}

void TestUdpRelayTransportPinsSourceAndRejectsMalformedDatagrams() {
    SOCKET relay = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET attacker = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    SOCKET client = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(relay != INVALID_SOCKET && attacker != INVALID_SOCKET &&
        client != INVALID_SOCKET);

    sockaddr_in relayAddress{};
    relayAddress.sin_family = AF_INET;
    relayAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sockaddr_in attackerAddress = relayAddress;
    sockaddr_in clientAddress = relayAddress;
    assert(bind(relay, reinterpret_cast<const sockaddr*>(&relayAddress),
        static_cast<int>(sizeof(relayAddress))) == 0);
    assert(bind(attacker, reinterpret_cast<const sockaddr*>(&attackerAddress),
        static_cast<int>(sizeof(attackerAddress))) == 0);
    assert(bind(client, reinterpret_cast<const sockaddr*>(&clientAddress),
        static_cast<int>(sizeof(clientAddress))) == 0);
    int relayLength = static_cast<int>(sizeof(relayAddress));
    int attackerLength = static_cast<int>(sizeof(attackerAddress));
    int clientLength = static_cast<int>(sizeof(clientAddress));
    assert(getsockname(relay, reinterpret_cast<sockaddr*>(&relayAddress),
        &relayLength) == 0);
    assert(getsockname(attacker, reinterpret_cast<sockaddr*>(&attackerAddress),
        &attackerLength) == 0);
    assert(getsockname(client, reinterpret_cast<sockaddr*>(&clientAddress),
        &clientLength) == 0);

    u_long nonBlocking = 1;
    assert(ioctlsocket(client, FIONBIO, &nonBlocking) == 0);
    std::array<std::uint8_t, 256> buffer{};
    Socks5UdpDatagramView view{};
    std::size_t receivedLength = 0;
    assert(ReceiveSocks5UdpFromRelay(client,
        reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
        buffer.data(), buffer.size(), view, receivedLength) ==
        Socks5UdpRelayIoResult::WouldBlock);

    const std::array<std::uint8_t, 4> target{203, 0, 113, 53};
    const std::array<std::uint8_t, 2> payload{0x12, 0x34};
    std::vector<std::uint8_t> datagram;
    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        target.data(), target.size(), 53, payload.data(), payload.size(),
        datagram) == Socks5UdpBuildResult::Valid);

    assert(sendto(relay, reinterpret_cast<const char*>(datagram.data()),
        static_cast<int>(datagram.size()), 0,
        reinterpret_cast<const sockaddr*>(&clientAddress),
        static_cast<int>(sizeof(clientAddress))) ==
        static_cast<int>(datagram.size()));
    assert(ReceiveSocks5UdpFromRelay(client,
        reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
        buffer.data(), buffer.size(), view, receivedLength) ==
        Socks5UdpRelayIoResult::Received);
    assert(receivedLength == datagram.size());
    assert(view.port == 53 && view.payloadLength == payload.size());
    assert(std::memcmp(view.payload, payload.data(), payload.size()) == 0);

    assert(sendto(attacker, reinterpret_cast<const char*>(datagram.data()),
        static_cast<int>(datagram.size()), 0,
        reinterpret_cast<const sockaddr*>(&clientAddress),
        static_cast<int>(sizeof(clientAddress))) ==
        static_cast<int>(datagram.size()));
    assert(ReceiveSocks5UdpFromRelay(client,
        reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
        buffer.data(), buffer.size(), view, receivedLength) ==
        Socks5UdpRelayIoResult::UnexpectedRelay);
    assert(receivedLength == 0);

    const std::array<std::uint8_t, 4> malformed{0, 0, 0, 5};
    assert(sendto(relay, reinterpret_cast<const char*>(malformed.data()),
        static_cast<int>(malformed.size()), 0,
        reinterpret_cast<const sockaddr*>(&clientAddress),
        static_cast<int>(sizeof(clientAddress))) ==
        static_cast<int>(malformed.size()));
    assert(ReceiveSocks5UdpFromRelay(client,
        reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
        buffer.data(), buffer.size(), view, receivedLength) ==
        Socks5UdpRelayIoResult::InvalidDatagram);

    const std::array<std::uint8_t, 64> oversized{};
    assert(sendto(relay, reinterpret_cast<const char*>(oversized.data()),
        static_cast<int>(oversized.size()), 0,
        reinterpret_cast<const sockaddr*>(&clientAddress),
        static_cast<int>(sizeof(clientAddress))) ==
        static_cast<int>(oversized.size()));
    assert(ReceiveSocks5UdpFromRelay(client,
        reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
        buffer.data(), 8, view, receivedLength) ==
        Socks5UdpRelayIoResult::BufferTooSmall);

    closesocket(client);
    closesocket(attacker);
    closesocket(relay);
}

void TestAssociationSourcePinningAndExpiry() {
    using Clock = Socks5UdpAssociation::Clock;
    const auto now = Clock::now();
    auto peer = V4(198, 51, 100, 7);
    Socks5UdpAssociation association;
    assert(association.Start(peer, 45000, std::chrono::seconds(30), 1200, now));

    auto client = V4(198, 51, 100, 7, 45000);
    assert(association.AuthorizeClientDatagram(client, 100, now) ==
        Socks5UdpAssociationResult::Accepted);
    assert(association.HasBoundClient());
    assert(association.BoundClient().port == 45000);

    auto wrongPort = V4(198, 51, 100, 7, 45001);
    assert(association.AuthorizeClientDatagram(wrongPort, 100, now) ==
        Socks5UdpAssociationResult::SourcePortMismatch);
    auto wrongAddress = V4(198, 51, 100, 8, 45000);
    assert(association.AuthorizeClientDatagram(wrongAddress, 100, now) ==
        Socks5UdpAssociationResult::SourceAddressMismatch);
    assert(association.AuthorizeClientDatagram(client, 1201, now) ==
        Socks5UdpAssociationResult::DatagramTooLarge);

    const auto expired = now + std::chrono::seconds(31);
    assert(!association.IsActive(expired));
    assert(association.AuthorizeClientDatagram(client, 10, expired) ==
        Socks5UdpAssociationResult::Inactive);
    assert(!association.HasBoundClient());

    assert(association.Start(peer, 0, std::chrono::seconds(30), 1200, now));
    auto learnedPort = V4(198, 51, 100, 7, 45002);
    assert(association.AuthorizeClientDatagram(learnedPort, 10, now) ==
        Socks5UdpAssociationResult::Accepted);
    association.OnControlClosed();
    assert(!association.IsActive(now));
}


bool ReceiveExactSocket(SOCKET socket, std::uint8_t* output, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        const int received = recv(socket,
            reinterpret_cast<char*>(output + offset),
            static_cast<int>(length - offset), 0);
        if (received <= 0) return false;
        offset += static_cast<std::size_t>(received);
    }
    return true;
}

bool SendAllSocket(SOCKET socket, const std::uint8_t* input, std::size_t length) {
    std::size_t offset = 0;
    while (offset < length) {
        const int sent = send(socket,
            reinterpret_cast<const char*>(input + offset),
            static_cast<int>(length - offset), 0);
        if (sent <= 0) return false;
        offset += static_cast<std::size_t>(sent);
    }
    return true;
}

void TestNonblockingSocks5UdpHandshake() {
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(listener != INVALID_SOCKET);
    sockaddr_in bindAddress{};
    bindAddress.sin_family = AF_INET;
    bindAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bindAddress.sin_port = 0;
    assert(bind(listener, reinterpret_cast<const sockaddr*>(&bindAddress),
        static_cast<int>(sizeof(bindAddress))) == 0);
    assert(listen(listener, 1) == 0);
    int bindLength = static_cast<int>(sizeof(bindAddress));
    assert(getsockname(listener, reinterpret_cast<sockaddr*>(&bindAddress),
        &bindLength) == 0);

    Socks5UdpSocket udpSocket;
    const auto udpOpen = udpSocket.Open(Socks5UdpEndpointFamily::Ipv4);
    assert(udpOpen == Socks5UdpSocketOpenResult::Opened);

    std::thread fakeSocksServer([listener]() {
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(listener, &readable);
        timeval acceptTimeout{5, 0};
        if (select(0, &readable, nullptr, nullptr, &acceptTimeout) <= 0) return;
        SOCKET peer = accept(listener, nullptr, nullptr);
        if (peer == INVALID_SOCKET) return;

        std::array<std::uint8_t, 3> greeting{};
        if (ReceiveExactSocket(peer, greeting.data(), greeting.size())) {
            const std::array<std::uint8_t, 2> methodReply{5, 0};
            const std::array<std::uint8_t, 3> expectedGreeting{5, 1, 0};
            if (greeting == expectedGreeting &&
                SendAllSocket(peer, methodReply.data(), methodReply.size())) {
                std::array<std::uint8_t, 10> associateRequest{};
                if (ReceiveExactSocket(peer, associateRequest.data(),
                        associateRequest.size())) {
                    const std::array<std::uint8_t, 10> associateReply{
                        5, 0, 0, 1, 127, 0, 0, 1, 0xA0, 0x01
                    };
                    if (associateRequest[0] == 5 &&
                        associateRequest[1] == 3 &&
                        associateRequest[2] == 0) {
                        SendAllSocket(peer, associateReply.data(),
                            associateReply.size());
                    }
                }
            }
        }
        std::uint8_t sink = 0;
        while (recv(peer, reinterpret_cast<char*>(&sink), 1, 0) > 0) {}
        closesocket(peer);
    });

    Socks5UdpAssociationClient association;
    const auto begin = association.BeginOpen(
        reinterpret_cast<const sockaddr*>(&bindAddress),
        static_cast<int>(sizeof(bindAddress)), udpSocket, 4000);
    if (begin != Socks5UdpAssociationAsyncResult::Pending) {
        association.Close();
        fakeSocksServer.join();
        udpSocket.Close();
        closesocket(listener);
        assert(begin == Socks5UdpAssociationAsyncResult::Pending);
        return;
    }

    auto result = Socks5UdpAssociationAsyncResult::Pending;
    const auto deadline = std::chrono::steady_clock::now() +
        std::chrono::seconds(4);
    while (result == Socks5UdpAssociationAsyncResult::Pending &&
           std::chrono::steady_clock::now() < deadline) {
        WSAPOLLFD descriptor{};
        descriptor.fd = association.ControlSocket();
        if (association.WantsRead()) descriptor.events |= POLLRDNORM;
        if (association.WantsWrite()) descriptor.events |= POLLWRNORM;
        const int ready = WSAPoll(&descriptor, 1, 100);
        if (ready == SOCKET_ERROR) break;
        if (ready == 0) {
            result = association.Advance(false, false);
            continue;
        }
        const bool readable = (descriptor.revents &
            (POLLRDNORM | POLLERR | POLLHUP)) != 0;
        const bool writable = (descriptor.revents &
            (POLLWRNORM | POLLERR | POLLHUP)) != 0;
        result = association.Advance(readable, writable);
    }

    const bool handshakeReady = result == Socks5UdpAssociationAsyncResult::Ready;
    const bool relayAddressValid = association.RelayAddress() != nullptr &&
        association.RelayAddress()->sa_family == AF_INET;
    const auto* relay = relayAddressValid
        ? reinterpret_cast<const sockaddr_in*>(association.RelayAddress()) : nullptr;
    const bool relayPortValid = relay != nullptr && ntohs(relay->sin_port) == 40961;

    association.Close();
    fakeSocksServer.join();
    udpSocket.Close();
    closesocket(listener);
    assert(handshakeReady);
    assert(relayAddressValid);
    assert(relayPortValid);
}

void TestAssociationManagerQuotasAndCleanup() {
    using Clock = Socks5UdpAssociation::Clock;
    const auto now = Clock::now();
    Socks5UdpAssociationManager manager(2, 1);
    const auto peerA = V4(203, 0, 113, 10, 1080);
    const auto peerB = V4(203, 0, 113, 11, 1080);

    assert(manager.Open(1, peerA, 0, std::chrono::seconds(5), 1400, now) ==
        Socks5UdpAssociationOpenResult::Opened);
    assert(manager.Open(2, peerA, 0, std::chrono::seconds(5), 1400, now) ==
        Socks5UdpAssociationOpenResult::PerPeerLimitReached);
    assert(manager.Open(2, peerB, 0, std::chrono::seconds(5), 1400, now) ==
        Socks5UdpAssociationOpenResult::Opened);
    assert(manager.Open(3, V4(203, 0, 113, 12), 0,
        std::chrono::seconds(5), 1400, now) ==
        Socks5UdpAssociationOpenResult::AssociationLimitReached);
    assert(manager.Open(1, peerB, 0, std::chrono::seconds(5), 1400, now) ==
        Socks5UdpAssociationOpenResult::DuplicateId);
    assert(manager.ActiveCount() == 2);

    assert(manager.Close(1));
    assert(!manager.Close(1));
    assert(manager.ActiveCount() == 1);
    assert(manager.SweepExpired(now + std::chrono::seconds(6)) == 1);
    assert(manager.ActiveCount() == 0);
}
}

int main() {
    WSADATA winsockData{};
    assert(WSAStartup(MAKEWORD(2, 2), &winsockData) == 0);
    TestDatagramRoundTrips();
    TestDatagramRejectsMalformedInput();
    TestAssociateControlMessages();
    TestRedirectContextDecodeRequiresValidUdpMetadata();
    TestUdpFlowManagerIdentityLimitsAndExpiry();
    TestUdpFlowRegistryForwardsFirstDatagramToSocksRelay();
    TestUdpRelayTransportPinsSourceAndRejectsMalformedDatagrams();
    TestAssociationSourcePinningAndExpiry();
    TestAssociationManagerQuotasAndCleanup();
    TestNonblockingSocks5UdpHandshake();
    WSACleanup();
    return 0;
}
