#include "../WfpTcpRedirect.h"
#include "../WfpSocks5Udp.h"
#include "../WfpSocks5UdpAssociation.h"
#include <chrono>

#include <cassert>
#include <cstdint>
#include <vector>

namespace {

FURIOUS_WFP_REDIRECT_CONTEXT MakeContext(
    FURIOUS_WFP_U16 family,
    FURIOUS_WFP_U8 protocol) {
    FURIOUS_WFP_REDIRECT_CONTEXT value = {};
    value.Magic = FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC;
    value.Size = sizeof(value);
    value.AbiVersion = FURIOUS_WFP_REDIRECT_ABI_VERSION;
    value.AddressFamily = family;
    value.Protocol = protocol;
    value.OriginalPortNetworkOrder = htons(443);
    value.OriginalProcessId = 1234;
    value.PolicyGeneration = 9;
    return value;
}

void TestIpv4ConnectRequest() {
    auto context = MakeContext(
        FURIOUS_WFP_REDIRECT_FAMILY_V4,
        FURIOUS_WFP_REDIRECT_PROTOCOL_TCP);
    context.OriginalAddress[0] = 192;
    context.OriginalAddress[1] = 0;
    context.OriginalAddress[2] = 2;
    context.OriginalAddress[3] = 10;

    std::vector<std::uint8_t> request;
    assert(furious::wfp::broker::BuildSocks5ConnectRequest(context, request));
    const std::vector<std::uint8_t> expected = {
        0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10, 0x01, 0xBB
    };
    assert(request == expected);
}

void TestIpv6ConnectRequest() {
    auto context = MakeContext(
        FURIOUS_WFP_REDIRECT_FAMILY_V6,
        FURIOUS_WFP_REDIRECT_PROTOCOL_TCP);
    context.OriginalAddress[0] = 0x20;
    context.OriginalAddress[1] = 0x01;
    context.OriginalAddress[15] = 0x01;

    std::vector<std::uint8_t> request;
    assert(furious::wfp::broker::BuildSocks5ConnectRequest(context, request));
    assert(request.size() == 22);
    assert(request[0] == 0x05 && request[1] == 0x01);
    assert(request[2] == 0x00 && request[3] == 0x04);
    assert(request[4] == 0x20 && request[5] == 0x01);
    assert(request[19] == 0x01);
    assert(request[20] == 0x01 && request[21] == 0xBB);
}

void TestRejectsInvalidOrUdpContext() {
    auto context = MakeContext(
        FURIOUS_WFP_REDIRECT_FAMILY_V4,
        FURIOUS_WFP_REDIRECT_PROTOCOL_TCP);
    context.OriginalAddress[0] = 203;
    context.OriginalAddress[1] = 0;
    context.OriginalAddress[2] = 113;
    context.OriginalAddress[3] = 7;

    std::vector<std::uint8_t> request;
    context.Magic ^= 1;
    assert(!furious::wfp::broker::BuildSocks5ConnectRequest(context, request));
    assert(request.empty());

    context.Magic ^= 1;
    context.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_UDP;
    assert(!furious::wfp::broker::BuildSocks5ConnectRequest(context, request));
    assert(request.empty());
}

struct SocketRegistrationProbe final {
    int registerCalls = 0;
    int unregisterCalls = 0;
};

bool RejectSocketRegistration(void* context, SOCKET) noexcept {
    auto* probe = static_cast<SocketRegistrationProbe*>(context);
    ++probe->registerCalls;
    return false;
}

void CountSocketUnregistration(void* context, SOCKET) noexcept {
    auto* probe = static_cast<SocketRegistrationProbe*>(context);
    ++probe->unregisterCalls;
}

void TestTunnelRegistrationFailureCancelsBeforeConnect() {
    WSADATA winsockData{};
    assert(WSAStartup(MAKEWORD(2, 2), &winsockData) == 0);
    sockaddr_in socksAddress{};
    socksAddress.sin_family = AF_INET;
    socksAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socksAddress.sin_port = htons(10808);

    furious::wfp::broker::RedirectedTcpConnection redirected;
    redirected.context = MakeContext(
        FURIOUS_WFP_REDIRECT_FAMILY_V4,
        FURIOUS_WFP_REDIRECT_PROTOCOL_TCP);
    redirected.context.OriginalAddress[0] = 192;
    redirected.context.OriginalAddress[1] = 0;
    redirected.context.OriginalAddress[2] = 2;
    redirected.context.OriginalAddress[3] = 1;
    redirected.redirectRecords.push_back(0x01);

    SocketRegistrationProbe probe;
    int error = 0;
    const SOCKET upstream = furious::wfp::broker::OpenSocks5Tunnel(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress),
        redirected,
        &error,
        &RejectSocketRegistration,
        &CountSocketUnregistration,
        &probe);

    assert(upstream == INVALID_SOCKET);
    (void)upstream; // Keep /W4 /WX clean when Release disables assert().
    assert(error == WSA_OPERATION_ABORTED);
    assert(probe.registerCalls == 1);
    assert(probe.unregisterCalls == 0);
    WSACleanup();
}

void TestTunnelRejectsUnpairedCancellationCallbacks() {
    WSADATA winsockData{};
    assert(WSAStartup(MAKEWORD(2, 2), &winsockData) == 0);
    sockaddr_in socksAddress{};
    socksAddress.sin_family = AF_INET;
    socksAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socksAddress.sin_port = htons(10808);

    furious::wfp::broker::RedirectedTcpConnection redirected;
    redirected.context = MakeContext(
        FURIOUS_WFP_REDIRECT_FAMILY_V4,
        FURIOUS_WFP_REDIRECT_PROTOCOL_TCP);
    redirected.redirectRecords.push_back(0x01);

    SocketRegistrationProbe probe;
    int error = 0;
    const SOCKET upstream = furious::wfp::broker::OpenSocks5Tunnel(
        reinterpret_cast<const sockaddr*>(&socksAddress),
        sizeof(socksAddress),
        redirected,
        &error,
        &RejectSocketRegistration,
        nullptr,
        &probe);

    assert(upstream == INVALID_SOCKET);
    (void)upstream; // Keep /W4 /WX clean when Release disables assert().
    assert(error == WSAEINVAL);
    assert(probe.registerCalls == 0);
    assert(probe.unregisterCalls == 0);
    WSACleanup();
}

} // namespace

void TestSocks5UdpParser() {
    using furious::wfp::broker::ParseSocks5UdpDatagram;
    using furious::wfp::broker::Socks5UdpAddressType;
    using furious::wfp::broker::Socks5UdpDatagramView;
    using furious::wfp::broker::Socks5UdpParseResult;

    Socks5UdpDatagramView view{};
    const std::vector<std::uint8_t> ipv4 = {
        0x00, 0x00, 0x00, 0x01, 192, 0, 2, 9, 0x01, 0xBB, 0xAA, 0xBB
    };
    assert(ParseSocks5UdpDatagram(ipv4.data(), ipv4.size(), view) ==
        Socks5UdpParseResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Ipv4);
    assert(view.addressLength == 4 && view.port == 443);
    assert(view.payloadLength == 2 && view.payload[0] == 0xAA);

    const std::vector<std::uint8_t> ipv6 = {
        0x00, 0x00, 0x00, 0x04,
        0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 0x13, 0x88, 0x7F
    };
    assert(ParseSocks5UdpDatagram(ipv6.data(), ipv6.size(), view) ==
        Socks5UdpParseResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Ipv6);
    assert(view.addressLength == 16 && view.port == 5000);
    assert(view.payloadLength == 1 && view.payload[0] == 0x7F);

    const std::vector<std::uint8_t> domain = {
        0x00, 0x00, 0x00, 0x03, 0x0B,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm',
        0x00, 0x35, 0x42
    };
    assert(ParseSocks5UdpDatagram(domain.data(), domain.size(), view) ==
        Socks5UdpParseResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Domain);
    assert(view.addressLength == 11 && view.port == 53);
    assert(view.payloadLength == 1 && view.payload[0] == 0x42);

    const std::vector<std::uint8_t> shortHeader = {0x00, 0x00, 0x00};
    assert(ParseSocks5UdpDatagram(shortHeader.data(), shortHeader.size(), view) ==
        Socks5UdpParseResult::Truncated);
    const std::vector<std::uint8_t> invalidReserved = {
        0x01, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 53
    };
    assert(ParseSocks5UdpDatagram(invalidReserved.data(), invalidReserved.size(), view) ==
        Socks5UdpParseResult::InvalidReservedField);
    const std::vector<std::uint8_t> fragmented = {0, 0, 1, 1, 127, 0, 0, 1, 0, 53};
    assert(ParseSocks5UdpDatagram(fragmented.data(), fragmented.size(), view) ==
        Socks5UdpParseResult::FragmentationUnsupported);
    const std::vector<std::uint8_t> unknownType = {0, 0, 0, 2};
    assert(ParseSocks5UdpDatagram(unknownType.data(), unknownType.size(), view) ==
        Socks5UdpParseResult::UnsupportedAddressType);
    const std::vector<std::uint8_t> emptyDomain = {0, 0, 0, 3, 0};
    assert(ParseSocks5UdpDatagram(emptyDomain.data(), emptyDomain.size(), view) ==
        Socks5UdpParseResult::EmptyDomain);
    const std::vector<std::uint8_t> missingPort = {0, 0, 0, 1, 127, 0, 0, 1, 0};
    assert(ParseSocks5UdpDatagram(missingPort.data(), missingPort.size(), view) ==
        Socks5UdpParseResult::Truncated);
    const std::vector<std::uint8_t> zeroPort = {0, 0, 0, 1, 127, 0, 0, 1, 0, 0};
    assert(ParseSocks5UdpDatagram(zeroPort.data(), zeroPort.size(), view) ==
        Socks5UdpParseResult::InvalidPort);
    assert(ParseSocks5UdpDatagram(nullptr, 0, view) ==
        Socks5UdpParseResult::NullDatagram);
    assert(view.address == nullptr && view.payload == nullptr);
    using furious::wfp::broker::BuildSocks5UdpDatagram;
    using furious::wfp::broker::Socks5UdpBuildResult;
    std::vector<std::uint8_t> built;
    const std::uint8_t ipv4Address[] = {192, 0, 2, 9};
    const std::uint8_t payload[] = {0xAA, 0xBB};
    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        ipv4Address, sizeof(ipv4Address), 443, payload, sizeof(payload), built) ==
        Socks5UdpBuildResult::Valid);
    assert(built == ipv4);
    assert(ParseSocks5UdpDatagram(built.data(), built.size(), view) ==
        Socks5UdpParseResult::Valid);
    assert(view.port == 443 && view.payloadLength == sizeof(payload));
    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        ipv4Address, 3, 443, payload, sizeof(payload), built) ==
        Socks5UdpBuildResult::InvalidAddressLength);
    assert(built.empty());
    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        ipv4Address, sizeof(ipv4Address), 0, payload, sizeof(payload), built) ==
        Socks5UdpBuildResult::InvalidPort);
    assert(built.empty());
    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        ipv4Address, sizeof(ipv4Address), 443, payload, sizeof(payload), built, 11) ==
        Socks5UdpBuildResult::DatagramTooLarge);
    assert(built.empty());
    assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
        ipv4Address, sizeof(ipv4Address), 443, nullptr, 1, built) ==
        Socks5UdpBuildResult::NullPayload);
    assert(built.empty());

}

void TestSocks5UdpAssociationLifecycle() {
    using namespace furious::wfp::broker;
    using Clock = Socks5UdpAssociation::Clock;
    const auto t = Clock::time_point{} + std::chrono::seconds(10);
    Socks5UdpEndpoint peer{};
    peer.family = Socks5UdpEndpointFamily::Ipv4;
    peer.address[0]=192; peer.address[2]=2; peer.address[3]=7; peer.port=51000;
    auto client=peer; client.port=62000;
    Socks5UdpAssociation a;
    assert(a.Start(peer, 0, std::chrono::seconds(30), 1200, t));
    auto spoof=client; spoof.address[3]=8;
    assert(a.AuthorizeClientDatagram(spoof, 10, t)==Socks5UdpAssociationResult::SourceAddressMismatch);
    assert(!a.HasBoundClient());
    assert(a.AuthorizeClientDatagram(client, 1201, t)==Socks5UdpAssociationResult::DatagramTooLarge);
    assert(a.AuthorizeClientDatagram(client, 10, t)==Socks5UdpAssociationResult::Accepted);
    assert(a.HasBoundClient() && a.BoundClient().port==62000);
    auto changed=client; changed.port=62001;
    assert(a.AuthorizeClientDatagram(changed, 10, t+std::chrono::seconds(1))==
        Socks5UdpAssociationResult::SourcePortMismatch);
    assert(a.IsActive(t+std::chrono::seconds(29)));
    assert(!a.IsActive(t+std::chrono::seconds(30)));
    assert(a.AuthorizeClientDatagram(client, 10, t+std::chrono::seconds(30))==
        Socks5UdpAssociationResult::Inactive);
    assert(a.Start(peer, 62000, std::chrono::seconds(5), 512, t));
    assert(a.AuthorizeClientDatagram(client, 10, t)==Socks5UdpAssociationResult::Accepted);
    a.OnControlClosed();
    assert(!a.IsActive(t) && a.MaximumDatagramLength()==0);
    Socks5UdpEndpoint peer6{}; peer6.family=Socks5UdpEndpointFamily::Ipv6;
    peer6.address[0]=0x20; peer6.address[1]=1; peer6.address[15]=1;
    auto client6=peer6; client6.port=53000;
    assert(a.Start(peer6, 0, std::chrono::seconds(5), 1400, t));
    assert(a.AuthorizeClientDatagram(client6, 64, t)==Socks5UdpAssociationResult::Accepted);
    assert(!a.Start(peer6, 0, std::chrono::milliseconds(0), 100, t));
}

void TestBrokerServerLifecycle();
void TestBrokerConcurrentStartStopIsSerialized();
void TestBrokerStopsWhileAcceptingConnections();

int main() {
    TestSocks5UdpParser();
    TestSocks5UdpAssociationLifecycle();
    TestIpv4ConnectRequest();
    TestIpv6ConnectRequest();
    TestRejectsInvalidOrUdpContext();
    TestTunnelRegistrationFailureCancelsBeforeConnect();
    TestTunnelRejectsUnpairedCancellationCallbacks();
    TestBrokerServerLifecycle();
    TestBrokerConcurrentStartStopIsSerialized();
    TestBrokerStopsWhileAcceptingConnections();
    return 0;
}
