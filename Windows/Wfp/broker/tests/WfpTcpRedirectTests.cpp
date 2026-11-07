#include "../WfpTcpRedirect.h"
#include "../WfpSocks5Udp.h"
#include "../WfpSocks5UdpAssociation.h"
#include "../WfpSocks5UdpAssociationManager.h"
#include "../WfpSocks5UdpSocket.h"
#include "../WfpSocks5UdpRedirectRecord.h"
#include "../WfpUdpFlowManager.h"
#include "../WfpSocks5UdpAssociationClient.h"
#include "../WfpSocks5UdpRelayTransport.h"
#include "../WfpSocks5UdpFlowRelay.h"
#include "../WfpSocks5UdpControl.h"
#include <chrono>
#include <atomic>
#include <cstring>
#include <thread>

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
    assert(a.Start(peer, 62001, std::chrono::seconds(5), 512, t));
    assert(a.AuthorizeClientDatagram(client, 10, t)==Socks5UdpAssociationResult::SourcePortMismatch);
    client.port = 62001;
    assert(a.AuthorizeClientDatagram(client, 10, t)==Socks5UdpAssociationResult::Accepted);
    a.OnControlClosed();
    assert(!a.IsActive(t) && a.MaximumDatagramLength()==0);
    Socks5UdpEndpoint peer6{}; peer6.family=Socks5UdpEndpointFamily::Ipv6;
    peer6.address[0]=0x20; peer6.address[1]=1; peer6.address[15]=1;
    auto client6=peer6; client6.port=53000;
    assert(a.Start(peer6, 0, std::chrono::seconds(5), 1400, t));
    assert(a.AuthorizeClientDatagram(client6, 64, t)==Socks5UdpAssociationResult::Accepted);
    assert(!a.Start(peer6, 0, std::chrono::milliseconds(0), 100, t));
    auto unspecified4 = peer;
    unspecified4.address = {};
    assert(!a.Start(unspecified4, 0, std::chrono::seconds(5), 100, t));
    auto multicast4 = peer;
    multicast4.address[0] = 239;
    assert(!a.Start(multicast4, 0, std::chrono::seconds(5), 100, t));
    auto reserved4 = peer;
    reserved4.address[0] = 240;
    assert(!a.Start(reserved4, 0, std::chrono::seconds(5), 100, t));
    auto unspecified6 = peer6;
    unspecified6.address = {};
    assert(!a.Start(unspecified6, 0, std::chrono::seconds(5), 100, t));
    auto multicast6 = peer6;
    multicast6.address[0] = 0xFF;
    assert(!a.Start(multicast6, 0, std::chrono::seconds(5), 100, t));
    assert(a.Start(peer, 0, std::chrono::seconds(5), 100, t));
    auto invalidSource = client;
    invalidSource.address[0] = 224;
    assert(a.AuthorizeClientDatagram(invalidSource, 10, t) ==
        Socks5UdpAssociationResult::InvalidSourceEndpoint);
    a.Close();
}
 
void TestSocks5UdpAssociationManagerLimitsAndExpiry() {
    using namespace furious::wfp::broker;
    using Clock = Socks5UdpAssociation::Clock;
    using OpenResult = Socks5UdpAssociationOpenResult;
    const auto now = Clock::time_point{} + std::chrono::seconds(100);

    Socks5UdpEndpoint peer{};
    peer.family = Socks5UdpEndpointFamily::Ipv4;
    peer.address[0] = 192;
    peer.address[2] = 2;
    peer.address[3] = 10;
    peer.port = 51000;
    auto samePeerDifferentPort = peer;
    samePeerDifferentPort.port = 51001;
    auto otherPeer = peer;
    otherPeer.address[3] = 11;

    Socks5UdpAssociationManager manager(2, 1);
    assert(manager.MaximumAssociations() == 2);
    assert(manager.MaximumAssociationsPerPeer() == 1);
    assert(manager.Open(0, peer, 0, std::chrono::seconds(10), 1200, now) ==
        OpenResult::InvalidId);
    assert(manager.Open(1, peer, 0, std::chrono::seconds(10), 1200, now) ==
        OpenResult::Opened);
    assert(manager.Open(1, peer, 0, std::chrono::seconds(10), 1200, now) ==
        OpenResult::DuplicateId);
    assert(manager.Open(2, samePeerDifferentPort, 0,
        std::chrono::seconds(10), 1200, now) == OpenResult::PerPeerLimitReached);
    assert(manager.Open(3, otherPeer, 0, std::chrono::seconds(10), 1200, now) ==
        OpenResult::Opened);
    auto thirdPeer = peer;
    thirdPeer.address[3] = 12;
    assert(manager.Open(4, thirdPeer, 0, std::chrono::seconds(10), 1200, now) ==
        OpenResult::AssociationLimitReached);
    assert(manager.ActiveCount() == 2);

    auto client = peer;
    client.port = 62000;
    assert(manager.AuthorizeClientDatagram(1, client, 32, now) ==
        Socks5UdpAssociationResult::Accepted);
    assert(manager.Close(1));
    assert(!manager.Close(1));
    assert(manager.ActiveCount() == 1);

    assert(manager.Open(4, peer, 0, std::chrono::seconds(10), 1200, now) ==
        OpenResult::Opened);
    assert(manager.ActiveCount() == 2);
    assert(manager.SweepExpired(now + std::chrono::seconds(10)) == 2);
    assert(manager.ActiveCount() == 0);
    assert(manager.AuthorizeClientDatagram(3, client, 32,
        now + std::chrono::seconds(10)) == Socks5UdpAssociationResult::Inactive);

    assert(manager.Open(5, peer, 0, std::chrono::seconds(10), 1200, now) ==
        OpenResult::Opened);
    assert(manager.RecordActivity(5, now + std::chrono::seconds(9)));
    assert(manager.SweepExpired(now + std::chrono::seconds(10)) == 0);
    assert(manager.SweepExpired(now + std::chrono::seconds(19)) == 1);
    assert(manager.ActiveCount() == 0);

    Socks5UdpAssociationManager concurrent(8, 1);
    std::atomic<int> opened{0};
    const auto openSamePeer = [&concurrent, &opened, &peer, now](std::uint64_t id) {
        if (concurrent.Open(id, peer, 0, std::chrono::seconds(10), 1200, now) ==
            OpenResult::Opened) {
            opened.fetch_add(1);
        }
    };
    std::thread first(openSamePeer, 10);
    std::thread second(openSamePeer, 11);
    first.join();
    second.join();
    assert(opened.load() == 1 && concurrent.ActiveCount() == 1);

    Socks5UdpAssociationManager disabled(0, 0);
    assert(disabled.Open(1, peer, 0, std::chrono::seconds(10), 1200, now) ==
        OpenResult::InvalidParameters);
}

void TestSocks5UdpSocketOwnership() {
    using namespace furious::wfp::broker;
    WSADATA winsockData{};
    assert(WSAStartup(MAKEWORD(2, 2), &winsockData) == 0);
    {
        Socks5UdpSocket ipv4;
        int error = 0;
        assert(ipv4.Open(Socks5UdpEndpointFamily::Ipv4, &error) ==
            Socks5UdpSocketOpenResult::Opened);
        assert(error == 0 && ipv4.IsOpen() && ipv4.NativeHandle() != INVALID_SOCKET);
        assert(ipv4.LocalPort() != 0);
        assert(ipv4.Family() == Socks5UdpEndpointFamily::Ipv4);
        sockaddr_in bound4{};
        int bound4Length = sizeof(bound4);
        assert(getsockname(ipv4.NativeHandle(),
            reinterpret_cast<sockaddr*>(&bound4), &bound4Length) == 0);
        assert(bound4.sin_family == AF_INET && ntohs(bound4.sin_port) == ipv4.LocalPort());
        assert(ipv4.Open(Socks5UdpEndpointFamily::Ipv4, &error) ==
            Socks5UdpSocketOpenResult::AlreadyOpen);
        ipv4.Close();
        ipv4.Close();
        assert(!ipv4.IsOpen() && ipv4.NativeHandle() == INVALID_SOCKET &&
            ipv4.LocalPort() == 0);
        assert(ipv4.Open(static_cast<Socks5UdpEndpointFamily>(0xFF), &error) ==
            Socks5UdpSocketOpenResult::UnsupportedAddressFamily);
        assert(error == WSAEAFNOSUPPORT && !ipv4.IsOpen());

        Socks5UdpSocket ipv6;
        const auto ipv6Result = ipv6.Open(Socks5UdpEndpointFamily::Ipv6, &error);
        if (ipv6Result == Socks5UdpSocketOpenResult::Opened) {
            assert(ipv6.LocalPort() != 0 && ipv6.IsOpen());
            sockaddr_in6 bound6{};
            int bound6Length = sizeof(bound6);
            assert(getsockname(ipv6.NativeHandle(),
                reinterpret_cast<sockaddr*>(&bound6), &bound6Length) == 0);
            assert(bound6.sin6_family == AF_INET6 &&
                ntohs(bound6.sin6_port) == ipv6.LocalPort());
        } else {
            assert(!ipv6.IsOpen() && ipv6.LocalPort() == 0);
            assert(error == WSAEAFNOSUPPORT || error == WSAEPROTONOSUPPORT ||
                error == WSAEADDRNOTAVAIL || error == WSAENOPROTOOPT);
        }
    }
    WSACleanup();
}

void TestWfpUdpRedirectContextDecode() {
    using namespace furious::wfp::broker;
    FURIOUS_WFP_REDIRECT_CONTEXT context{};
    context.Magic = FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC;
    context.Size = sizeof(context);
    context.AbiVersion = FURIOUS_WFP_REDIRECT_ABI_VERSION;
    context.AddressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V4;
    context.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_UDP;
    context.OriginalPortNetworkOrder = htons(53);
    context.OriginalAddress[0] = 192;
    context.OriginalAddress[1] = 0;
    context.OriginalAddress[2] = 2;
    context.OriginalAddress[3] = 53;
    context.OriginalProcessId = 1234;
    context.RulePriority = 10;
    context.PolicyGeneration = 42;

    std::vector<std::uint8_t> bytes(sizeof(context));
    std::memcpy(bytes.data(), &context, sizeof(context));
    FURIOUS_WFP_REDIRECT_CONTEXT decoded{};
    assert(DecodeWfpUdpRedirectContext(bytes, decoded) ==
        WfpUdpRedirectContextDecodeResult::Decoded);
    assert(decoded.OriginalProcessId == context.OriginalProcessId);
    assert(decoded.OriginalPortNetworkOrder == context.OriginalPortNetworkOrder);
    assert(decoded.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4);

    auto invalidSize = bytes;
    invalidSize.pop_back();
    assert(DecodeWfpUdpRedirectContext(invalidSize, decoded) ==
        WfpUdpRedirectContextDecodeResult::InvalidSize);
    assert(decoded.Magic == 0);

    auto invalidContext = context;
    invalidContext.Magic = 0;
    std::memcpy(bytes.data(), &invalidContext, sizeof(invalidContext));
    assert(DecodeWfpUdpRedirectContext(bytes, decoded) ==
        WfpUdpRedirectContextDecodeResult::InvalidContext);
    assert(decoded.Magic == 0);

    auto tcpContext = context;
    tcpContext.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_TCP;
    std::memcpy(bytes.data(), &tcpContext, sizeof(tcpContext));
    assert(DecodeWfpUdpRedirectContext(bytes, decoded) ==
        WfpUdpRedirectContextDecodeResult::NotUdp);
    assert(decoded.Magic == 0);

    auto ipv6Context = context;
    ipv6Context.AddressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V6;
    for (std::size_t i = 0; i < sizeof(ipv6Context.OriginalAddress); ++i) {
        ipv6Context.OriginalAddress[i] = static_cast<std::uint8_t>(i + 1);
    }
    std::memcpy(bytes.data(), &ipv6Context, sizeof(ipv6Context));
    assert(DecodeWfpUdpRedirectContext(bytes, decoded) ==
        WfpUdpRedirectContextDecodeResult::Decoded);
    assert(decoded.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V6);
}

void TestSocks5UdpAssociationClientHandshake() {
    using namespace furious::wfp::broker;
    WSADATA data{};
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    {
        SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        assert(listener != INVALID_SOCKET);
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        serverAddress.sin_port = 0;
        assert(bind(listener, reinterpret_cast<const sockaddr*>(&serverAddress),
            sizeof(serverAddress)) == 0);
        assert(listen(listener, 1) == 0);
        int serverAddressLength = sizeof(serverAddress);
        assert(getsockname(listener, reinterpret_cast<sockaddr*>(&serverAddress),
            &serverAddressLength) == 0);

        Socks5UdpSocket localUdp;
        int socketError = 0;
        assert(localUdp.Open(Socks5UdpEndpointFamily::Ipv4, &socketError) ==
            Socks5UdpSocketOpenResult::Opened);
        std::atomic<std::uint16_t> requestedPort{0};
        std::thread fakeSocksServer([&]() {
            SOCKET accepted = accept(listener, nullptr, nullptr);
            assert(accepted != INVALID_SOCKET);
            DWORD timeout = 5000;
            setsockopt(accepted, SOL_SOCKET, SO_RCVTIMEO,
                reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            std::uint8_t greeting[3]{};
            assert(recv(accepted, reinterpret_cast<char*>(greeting),
                sizeof(greeting), MSG_WAITALL) == static_cast<int>(sizeof(greeting)));
            assert(greeting[0] == 0x05 && greeting[1] == 0x01 && greeting[2] == 0x00);
            const std::uint8_t greetingReply[] = {0x05, 0x00};
            assert(send(accepted, reinterpret_cast<const char*>(greetingReply),
                sizeof(greetingReply), 0) == static_cast<int>(sizeof(greetingReply)));

            std::uint8_t request[10]{};
            assert(recv(accepted, reinterpret_cast<char*>(request),
                sizeof(request), MSG_WAITALL) == static_cast<int>(sizeof(request)));
            assert(request[0] == 0x05 && request[1] == 0x03 &&
                request[2] == 0x00 && request[3] == 0x01);
            assert(request[4] == 127 && request[5] == 0 &&
                request[6] == 0 && request[7] == 1);
            requestedPort.store(static_cast<std::uint16_t>(
                (static_cast<std::uint16_t>(request[8]) << 8) | request[9]));

            const std::uint8_t associateReply[] = {
                0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x43, 0x21
            };
            assert(send(accepted, reinterpret_cast<const char*>(associateReply),
                sizeof(associateReply), 0) == static_cast<int>(sizeof(associateReply)));
            char closeProbe = 0;
            (void)recv(accepted, &closeProbe, 1, 0);
            closesocket(accepted);
        });

        Socks5UdpAssociationClient client;
        const auto result = client.Open(
            reinterpret_cast<const sockaddr*>(&serverAddress), sizeof(serverAddress),
            localUdp, 5000, &socketError);
        assert(result == Socks5UdpAssociationClientOpenResult::Opened);
        assert(socketError == 0 && client.IsOpen() && client.IsControlAlive());
        assert(client.RelayAddress() != nullptr);
        const auto* relay = reinterpret_cast<const sockaddr_in*>(client.RelayAddress());
        assert(relay->sin_family == AF_INET);
        assert(relay->sin_addr.s_addr == htonl(INADDR_LOOPBACK));
        assert(ntohs(relay->sin_port) == 0x4321);
        assert(requestedPort.load() == localUdp.LocalPort());

        client.Close();
        assert(!client.IsOpen() && client.ControlSocket() == INVALID_SOCKET);
        fakeSocksServer.join();
        closesocket(listener);
    }
    WSACleanup();
}

void TestSocks5UdpRelayTransportLoopback() {
    using namespace furious::wfp::broker;
    WSADATA data{};
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    {
        SOCKET relay = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SOCKET client = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SOCKET attacker = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        assert(relay != INVALID_SOCKET && client != INVALID_SOCKET &&
            attacker != INVALID_SOCKET);

        sockaddr_in relayAddress{};
        relayAddress.sin_family = AF_INET;
        relayAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        relayAddress.sin_port = 0;
        assert(bind(relay, reinterpret_cast<const sockaddr*>(&relayAddress),
            sizeof(relayAddress)) == 0);
        int relayLength = sizeof(relayAddress);
        assert(getsockname(relay, reinterpret_cast<sockaddr*>(&relayAddress),
            &relayLength) == 0);

        const std::uint8_t target[] = {203, 0, 113, 7};
        const std::uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
        int error = 0;
        assert(SendSocks5UdpToRelay(client,
            reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
            Socks5UdpAddressType::Ipv4, target, sizeof(target), 5353,
            payload, sizeof(payload), 1400, &error) == Socks5UdpRelayIoResult::Sent);
        assert(error == 0);

        std::uint8_t relayBuffer[128]{};
        sockaddr_in clientAddress{};
        int clientLength = sizeof(clientAddress);
        const int requestLength = recvfrom(relay,
            reinterpret_cast<char*>(relayBuffer), sizeof(relayBuffer), 0,
            reinterpret_cast<sockaddr*>(&clientAddress), &clientLength);
        assert(requestLength > 0);
        Socks5UdpDatagramView request{};
        assert(ParseSocks5UdpDatagram(relayBuffer,
            static_cast<std::size_t>(requestLength), request) == Socks5UdpParseResult::Valid);
        assert(request.addressType == Socks5UdpAddressType::Ipv4 &&
            request.addressLength == sizeof(target) && request.port == 5353 &&
            request.payloadLength == sizeof(payload));
        assert(std::memcmp(request.address, target, sizeof(target)) == 0);
        assert(std::memcmp(request.payload, payload, sizeof(payload)) == 0);

        std::vector<std::uint8_t> response;
        assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
            target, sizeof(target), 5353, payload, sizeof(payload),
            response, 1400) == Socks5UdpBuildResult::Valid);
        assert(sendto(relay, reinterpret_cast<const char*>(response.data()),
            static_cast<int>(response.size()), 0,
            reinterpret_cast<const sockaddr*>(&clientAddress), sizeof(clientAddress)) ==
            static_cast<int>(response.size()));

        std::uint8_t receiveBuffer[128]{};
        Socks5UdpDatagramView received{};
        std::size_t receivedLength = 0;
        assert(ReceiveSocks5UdpFromRelay(client,
            reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
            receiveBuffer, sizeof(receiveBuffer), received, receivedLength, &error) ==
            Socks5UdpRelayIoResult::Received);
        assert(error == 0 && receivedLength == response.size());
        assert(received.port == 5353 && received.payloadLength == sizeof(payload));
        assert(std::memcmp(received.payload, payload, sizeof(payload)) == 0);

        // Exact-capacity datagrams are valid; only actual truncation is rejected.
        std::uint8_t exactBuffer[22]{};
        const std::uint8_t exactPayload[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
        std::vector<std::uint8_t> exactResponse;
        assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
            target, sizeof(target), 5353, exactPayload, sizeof(exactPayload),
            exactResponse, sizeof(exactBuffer)) == Socks5UdpBuildResult::Valid);
        assert(exactResponse.size() == sizeof(exactBuffer));
        assert(sendto(relay, reinterpret_cast<const char*>(exactResponse.data()),
            static_cast<int>(exactResponse.size()), 0,
            reinterpret_cast<const sockaddr*>(&clientAddress), sizeof(clientAddress)) ==
            static_cast<int>(exactResponse.size()));
        assert(ReceiveSocks5UdpFromRelay(client,
            reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
            exactBuffer, sizeof(exactBuffer), received, receivedLength, &error) ==
            Socks5UdpRelayIoResult::Received);
        assert(receivedLength == sizeof(exactBuffer));

        std::uint8_t tooSmallBuffer[21]{};
        assert(sendto(relay, reinterpret_cast<const char*>(exactResponse.data()),
            static_cast<int>(exactResponse.size()), 0,
            reinterpret_cast<const sockaddr*>(&clientAddress), sizeof(clientAddress)) ==
            static_cast<int>(exactResponse.size()));
        assert(ReceiveSocks5UdpFromRelay(client,
            reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
            tooSmallBuffer, sizeof(tooSmallBuffer), received, receivedLength, &error) ==
            Socks5UdpRelayIoResult::BufferTooSmall);
        assert(receivedLength == 0 && received.address == nullptr);

        // A datagram from any other source is rejected before parsing.
        assert(sendto(attacker, reinterpret_cast<const char*>(response.data()),
            static_cast<int>(response.size()), 0,
            reinterpret_cast<const sockaddr*>(&clientAddress), sizeof(clientAddress)) ==
            static_cast<int>(response.size()));
        assert(ReceiveSocks5UdpFromRelay(client,
            reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
            receiveBuffer, sizeof(receiveBuffer), received, receivedLength, &error) ==
            Socks5UdpRelayIoResult::UnexpectedRelay);
        assert(receivedLength == 0 && received.address == nullptr);

        u_long nonblocking = 1;
        assert(ioctlsocket(client, FIONBIO, &nonblocking) == 0);
        assert(ReceiveSocks5UdpFromRelay(client,
            reinterpret_cast<const sockaddr*>(&relayAddress), sizeof(relayAddress),
            receiveBuffer, sizeof(receiveBuffer), received, receivedLength, &error) ==
            Socks5UdpRelayIoResult::WouldBlock);
        assert(error == WSAEWOULDBLOCK);

        closesocket(attacker);
        closesocket(client);
        closesocket(relay);
    }
    WSACleanup();
}

void TestSocks5UdpFlowRelayBridge() {
    using namespace furious::wfp::broker;
    WSADATA data{};
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    SOCKET udpRelay = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(listener != INVALID_SOCKET && udpRelay != INVALID_SOCKET);

    sockaddr_in tcpAddress{};
    tcpAddress.sin_family = AF_INET;
    tcpAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(listener, reinterpret_cast<const sockaddr*>(&tcpAddress),
        sizeof(tcpAddress)) == 0);
    int tcpLength = sizeof(tcpAddress);
    assert(getsockname(listener, reinterpret_cast<sockaddr*>(&tcpAddress),
        &tcpLength) == 0);
    assert(listen(listener, 1) == 0);

    sockaddr_in udpAddress{};
    udpAddress.sin_family = AF_INET;
    udpAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(udpRelay, reinterpret_cast<const sockaddr*>(&udpAddress),
        sizeof(udpAddress)) == 0);
    int udpLength = sizeof(udpAddress);
    assert(getsockname(udpRelay, reinterpret_cast<sockaddr*>(&udpAddress),
        &udpLength) == 0);

    std::atomic<bool> serverOk{false};
    std::atomic<bool> allowServerClose{false};
    std::thread fakeSocksServer([&]() {
        SOCKET control = accept(listener, nullptr, nullptr);
        assert(control != INVALID_SOCKET);
        std::uint8_t greeting[3]{};
        assert(recv(control, reinterpret_cast<char*>(greeting), sizeof(greeting), 0) ==
            static_cast<int>(sizeof(greeting)));
        assert(greeting[0] == 5 && greeting[1] == 1 && greeting[2] == 0);
        const std::uint8_t methodReply[] = {5, 0};
        assert(send(control, reinterpret_cast<const char*>(methodReply),
            sizeof(methodReply), 0) == static_cast<int>(sizeof(methodReply)));

        std::uint8_t request[10]{};
        assert(recv(control, reinterpret_cast<char*>(request), sizeof(request), 0) ==
            static_cast<int>(sizeof(request)));
        assert(request[0] == 5 && request[1] == 3 && request[3] == 1);
        assert(request[8] != 0 || request[9] != 0);

        const std::uint16_t port = ntohs(udpAddress.sin_port);
        const std::uint8_t reply[] = {
            5, 0, 0, 1, 127, 0, 0, 1,
            static_cast<std::uint8_t>(port >> 8),
            static_cast<std::uint8_t>(port & 0xFF)
        };
        assert(send(control, reinterpret_cast<const char*>(reply),
            sizeof(reply), 0) == static_cast<int>(sizeof(reply)));

        std::uint8_t packet[256]{};
        sockaddr_in client{};
        int clientLength = sizeof(client);
        const int packetLength = recvfrom(udpRelay, reinterpret_cast<char*>(packet),
            sizeof(packet), 0, reinterpret_cast<sockaddr*>(&client), &clientLength);
        assert(packetLength > 0);
        Socks5UdpDatagramView requestView{};
        assert(ParseSocks5UdpDatagram(packet, static_cast<std::size_t>(packetLength),
            requestView) == Socks5UdpParseResult::Valid);
        const std::uint8_t target[] = {203, 0, 113, 7};
        const std::uint8_t payload[] = {0xCA, 0xFE, 0xBA, 0xBE};
        assert(requestView.addressType == Socks5UdpAddressType::Ipv4);
        assert(requestView.addressLength == sizeof(target) &&
            std::memcmp(requestView.address, target, sizeof(target)) == 0);
        assert(requestView.port == 443 && requestView.payloadLength == sizeof(payload));
        assert(std::memcmp(requestView.payload, payload, sizeof(payload)) == 0);

        const std::uint8_t wrongTarget[] = {203, 0, 113, 8};
        std::vector<std::uint8_t> wrongResponse;
        assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
            wrongTarget, sizeof(wrongTarget), 443, payload, sizeof(payload),
            wrongResponse) == Socks5UdpBuildResult::Valid);
        assert(sendto(udpRelay, reinterpret_cast<const char*>(wrongResponse.data()),
            static_cast<int>(wrongResponse.size()), 0,
            reinterpret_cast<const sockaddr*>(&client), sizeof(client)) ==
            static_cast<int>(wrongResponse.size()));

        std::vector<std::uint8_t> response;
        assert(BuildSocks5UdpDatagram(Socks5UdpAddressType::Ipv4,
            target, sizeof(target), 443, payload, sizeof(payload),
            response) == Socks5UdpBuildResult::Valid);
        assert(sendto(udpRelay, reinterpret_cast<const char*>(response.data()),
            static_cast<int>(response.size()), 0,
            reinterpret_cast<const sockaddr*>(&client), sizeof(client)) ==
            static_cast<int>(response.size()));
        serverOk.store(true);
        while (!allowServerClose.load()) std::this_thread::yield();
        closesocket(control);
    });

    WfpSocks5UdpFlowRelay bridge;
    sockaddr_in clientAddress{};
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    clientAddress.sin_port = htons(40000);
    auto context = MakeContext(FURIOUS_WFP_REDIRECT_FAMILY_V4,
        FURIOUS_WFP_REDIRECT_PROTOCOL_UDP);
    context.OriginalPortNetworkOrder = htons(443);
    context.OriginalAddress[0] = 203;
    context.OriginalAddress[1] = 0;
    context.OriginalAddress[2] = 113;
    context.OriginalAddress[3] = 7;
    const std::vector<std::uint8_t> redirectRecord{0x11, 0x22, 0x33};
    int error = 0;
    assert(bridge.Open(reinterpret_cast<const sockaddr*>(&tcpAddress),
        sizeof(tcpAddress), reinterpret_cast<const sockaddr*>(&clientAddress),
        sizeof(clientAddress), context, redirectRecord, 3000, &error) ==
        WfpSocks5UdpFlowRelayResult::Ready);
    const std::uint8_t payload[] = {0xCA, 0xFE, 0xBA, 0xBE};
    assert(bridge.SendClientPayload(payload, sizeof(payload), &error) ==
        WfpSocks5UdpFlowRelayResult::Ready);

    std::uint8_t receiveBuffer[256]{};
    Socks5UdpDatagramView response{};
    std::size_t receivedLength = 0;
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(bridge.UdpSocket(), &readable);
    timeval timeout{3, 0};
    assert(select(0, &readable, nullptr, nullptr, &timeout) == 1);
    assert(bridge.ReceiveUpstreamResponse(receiveBuffer, sizeof(receiveBuffer),
        response, receivedLength, &error) ==
        WfpSocks5UdpFlowRelayResult::UnexpectedDestination);
    assert(receivedLength == 0);

    FD_ZERO(&readable);
    FD_SET(bridge.UdpSocket(), &readable);
    timeout = timeval{3, 0};
    assert(select(0, &readable, nullptr, nullptr, &timeout) == 1);
    assert(bridge.ReceiveUpstreamResponse(receiveBuffer, sizeof(receiveBuffer),
        response, receivedLength, &error) == WfpSocks5UdpFlowRelayResult::Ready);
    assert(receivedLength > 0 && response.port == 443);
    assert(response.payloadLength == sizeof(payload));
    assert(std::memcmp(response.payload, payload, sizeof(payload)) == 0);
    assert(bridge.IsOpen());
    bridge.Close();
    assert(!bridge.IsOpen());
    allowServerClose.store(true);
    fakeSocksServer.join();
    assert(serverOk.load());
    closesocket(udpRelay);
    closesocket(listener);
    WSACleanup();
}

void TestWfpUdpFlowManager() {
    using namespace furious::wfp::broker;
    using Clock = WfpUdpFlowManager::Clock;
    using CreateResult = WfpUdpFlowCreateResult;
    using TouchResult = WfpUdpFlowTouchResult;
    const auto now = Clock::time_point{} + std::chrono::seconds(100);

    sockaddr_in source{};
    source.sin_family = AF_INET;
    source.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    source.sin_port = htons(50000);
    auto secondSource = source;
    secondSource.sin_port = htons(50001);
    auto thirdSource = source;
    thirdSource.sin_port = htons(50002);

    FURIOUS_WFP_REDIRECT_CONTEXT context{};
    context.Magic = FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC;
    context.Size = static_cast<FURIOUS_WFP_U32>(sizeof(context));
    context.AbiVersion = FURIOUS_WFP_REDIRECT_ABI_VERSION;
    context.AddressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V4;
    context.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_UDP;
    context.OriginalPortNetworkOrder = htons(53);
    context.OriginalAddress[0] = 8;
    context.OriginalAddress[1] = 8;
    context.OriginalAddress[2] = 8;
    context.OriginalAddress[3] = 8;
    context.OriginalProcessId = 1001;
    context.PolicyGeneration = 7;
    const std::vector<std::uint8_t> record{0x11, 0x22, 0x33};

    WfpUdpFlowManager manager(2, 1, std::chrono::seconds(10));
    assert(manager.MaximumFlows() == 2);
    assert(manager.MaximumFlowsPerProcess() == 1);
    std::uint64_t firstId = 0;
    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&source),
        sizeof(source), context, record, now, firstId) == CreateResult::Created);
    assert(firstId != 0 && manager.ActiveCount() == 1);

    std::uint64_t duplicateId = 0;
    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&source),
        sizeof(source), context, record, now + std::chrono::seconds(1), duplicateId) ==
        CreateResult::ExistingFlow);
    assert(duplicateId == firstId);

    auto conflictingContext = context;
    conflictingContext.OriginalAddress[3] = 9;
    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&source),
        sizeof(source), conflictingContext, record, now + std::chrono::seconds(2), duplicateId) ==
        CreateResult::SourceEndpointConflict);

    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&secondSource),
        sizeof(secondSource), context, record, now + std::chrono::seconds(3), duplicateId) ==
        CreateResult::PerProcessLimitReached);

    auto secondProcessContext = context;
    secondProcessContext.OriginalProcessId = 2002;
    std::uint64_t secondId = 0;
    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&secondSource),
        sizeof(secondSource), secondProcessContext, record, now + std::chrono::seconds(4), secondId) ==
        CreateResult::Created);
    assert(manager.ActiveCount() == 2);

    auto thirdProcessContext = context;
    thirdProcessContext.OriginalProcessId = 3003;
    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&thirdSource),
        sizeof(thirdSource), thirdProcessContext, record, now + std::chrono::seconds(5), duplicateId) ==
        CreateResult::FlowLimitReached);

    std::uint64_t touchedId = 0;
    assert(manager.Touch(reinterpret_cast<const sockaddr*>(&source), sizeof(source),
        now + std::chrono::seconds(9), touchedId) == TouchResult::Found);
    assert(touchedId == firstId);

    WfpUdpFlowSnapshot snapshot{};
    assert(manager.GetSnapshot(firstId, snapshot));
    assert(snapshot.redirectContext.OriginalProcessId == 1001);
    assert(snapshot.redirectRecord == record);
    assert(snapshot.sourceEndpoint.ss_family == AF_INET);

    assert(manager.SweepExpired(now + std::chrono::seconds(14)) == 1);
    assert(manager.ActiveCount() == 1);
    assert(manager.Touch(reinterpret_cast<const sockaddr*>(&source), sizeof(source),
        now + std::chrono::seconds(19), touchedId) == TouchResult::Expired);
    assert(manager.ActiveCount() == 0);

    sockaddr_in oversizedSource = source;
    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&oversizedSource),
        sizeof(sockaddr_storage), context, record, now, duplicateId) ==
        CreateResult::InvalidSource);

    sockaddr_in invalidSource = source;
    invalidSource.sin_port = 0;
    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&invalidSource),
        sizeof(invalidSource), context, record, now + std::chrono::seconds(20), duplicateId) ==
        CreateResult::InvalidSource);
    assert(manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&source),
        sizeof(source), context, {}, now + std::chrono::seconds(20), duplicateId) ==
        CreateResult::MissingRedirectRecord);

    sockaddr_in6 source6{};
    source6.sin6_family = AF_INET6;
    source6.sin6_addr = in6addr_loopback;
    source6.sin6_port = htons(50003);
    auto context6 = context;
    context6.AddressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V6;
    for (std::size_t i = 0; i < sizeof(context6.OriginalAddress); ++i) {
        context6.OriginalAddress[i] = static_cast<std::uint8_t>(i + 1);
    }
    context6.OriginalProcessId = 4004;
    WfpUdpFlowManager ipv6Manager(4, 2, std::chrono::seconds(10));
    std::uint64_t ipv6Id = 0;
    assert(ipv6Manager.RegisterFirstDatagram(reinterpret_cast<const sockaddr*>(&source6),
        sizeof(source6), context6, record, now, ipv6Id) == CreateResult::Created);
    assert(ipv6Manager.ActiveCount() == 1);

    WfpUdpFlowManager concurrent(8, 1, std::chrono::seconds(10));
    std::atomic<int> created{0};
    std::atomic<int> existing{0};
    const auto registerSame = [&concurrent, &created, &existing, &source,
        &context, &record, now]() {
        std::uint64_t id = 0;
        const auto result = concurrent.RegisterFirstDatagram(
            reinterpret_cast<const sockaddr*>(&source), sizeof(source),
            context, record, now, id);
        if (result == CreateResult::Created) created.fetch_add(1);
        if (result == CreateResult::ExistingFlow) existing.fetch_add(1);
    };
    std::thread first(registerSame);
    std::thread second(registerSame);
    first.join();
    second.join();
    assert(created.load() == 1 && existing.load() == 1);
    assert(concurrent.ActiveCount() == 1);
}
 
void TestWfpUdpMessageReceive() {
    using namespace furious::wfp::broker;
    WSADATA data{};
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    {
        SOCKET receiver = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        SOCKET sender = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        assert(receiver != INVALID_SOCKET && sender != INVALID_SOCKET);

        sockaddr_in receiverAddress{};
        receiverAddress.sin_family = AF_INET;
        receiverAddress.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        receiverAddress.sin_port = 0;
        assert(bind(receiver, reinterpret_cast<const sockaddr*>(&receiverAddress),
            sizeof(receiverAddress)) == 0);
        int receiverAddressLength = sizeof(receiverAddress);
        assert(getsockname(receiver, reinterpret_cast<sockaddr*>(&receiverAddress),
            &receiverAddressLength) == 0);
        assert(ntohs(receiverAddress.sin_port) != 0);

        LPFN_WSARECVMSG receiveMessage = nullptr;
        assert(ResolveWsaRecvMsg(receiver, &receiveMessage) == 0);
        assert(receiveMessage != nullptr);

        const std::uint8_t expected[] = {0x01, 0x02, 0x03, 0x04, 0x05};
        assert(sendto(sender, reinterpret_cast<const char*>(expected),
            sizeof(expected), 0, reinterpret_cast<const sockaddr*>(&receiverAddress),
            sizeof(receiverAddress)) == static_cast<int>(sizeof(expected)));

        std::uint8_t payload[64]{};
        std::vector<char> control(WSA_CMSG_SPACE(1024));
        WfpUdpReceivedMessage received{};
        int error = 0;
        assert(ReceiveWfpUdpMessage(receiver, receiveMessage, payload,
            sizeof(payload), control.data(), control.size(), received, &error) ==
            WfpUdpReceiveResult::Received);
        assert(error == 0 && received.payloadLength == sizeof(expected));
        assert(received.sourceAddress.ss_family == AF_INET);
        assert(std::memcmp(payload, expected, sizeof(expected)) == 0);
        assert(received.redirectRecord.empty() && received.redirectContext.empty());

        u_long nonblocking = 1;
        assert(ioctlsocket(receiver, FIONBIO, &nonblocking) == 0);
        assert(ReceiveWfpUdpMessage(receiver, receiveMessage, payload,
            sizeof(payload), control.data(), control.size(), received, &error) ==
            WfpUdpReceiveResult::WouldBlock);
        assert(error == WSAEWOULDBLOCK);

        closesocket(sender);
        closesocket(receiver);
    }
    WSACleanup();
}

void TestWfpUdpRedirectRecordAncillaryData() {
    using namespace furious::wfp::broker;
    std::vector<std::uint8_t> extractedRecord;
    std::vector<std::uint8_t> extractedContext;
    WSAMSG message{};
    assert(ExtractWfpUdpRedirectRecord(message, extractedRecord) ==
        WfpUdpRedirectRecordResult::NotPresent);
    assert(ExtractWfpUdpRedirectContext(message, extractedContext) ==
        WfpUdpRedirectRecordResult::NotPresent);
    assert(extractedRecord.empty() && extractedContext.empty());

    const std::uint8_t record[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    const std::uint8_t context[] = {0xA1, 0xB2, 0xC3};
    const std::size_t controlLength =
        WSA_CMSG_SPACE(sizeof(record)) + WSA_CMSG_SPACE(sizeof(context));
    std::vector<char> controlBuffer(controlLength);
    message.Control.buf = controlBuffer.data();
    message.Control.len = static_cast<ULONG>(controlBuffer.size());
    WSACMSGHDR* header = WSA_CMSG_FIRSTHDR(&message);
    assert(header != nullptr);
    header->cmsg_level = IPPROTO_IP;
    header->cmsg_type = IP_WFP_REDIRECT_RECORDS;
    header->cmsg_len = WSA_CMSG_LEN(sizeof(record));
    std::memcpy(WSA_CMSG_DATA(header), record, sizeof(record));
    WSACMSGHDR* contextHeader = WSA_CMSG_NXTHDR(&message, header);
    assert(contextHeader != nullptr);
    contextHeader->cmsg_level = IPPROTO_IP;
    contextHeader->cmsg_type = IP_WFP_REDIRECT_CONTEXT;
    contextHeader->cmsg_len = WSA_CMSG_LEN(sizeof(context));
    std::memcpy(WSA_CMSG_DATA(contextHeader), context, sizeof(context));

    assert(ExtractWfpUdpRedirectRecord(message, extractedRecord) ==
        WfpUdpRedirectRecordResult::Present);
    assert(extractedRecord.size() == sizeof(record));
    assert(std::memcmp(extractedRecord.data(), record, sizeof(record)) == 0);
    assert(ExtractWfpUdpRedirectContext(message, extractedContext) ==
        WfpUdpRedirectRecordResult::Present);
    assert(extractedContext.size() == sizeof(context));
    assert(std::memcmp(extractedContext.data(), context, sizeof(context)) == 0);

    header->cmsg_len = 0;
    assert(ExtractWfpUdpRedirectRecord(message, extractedRecord) ==
        WfpUdpRedirectRecordResult::InvalidMessage);
    assert(extractedRecord.empty());

    message.Control.buf = nullptr;
    message.Control.len = 0;
    LPFN_WSARECVMSG receiveMessage = nullptr;
    LPFN_WSASENDMSG sendMessage = nullptr;
    WSADATA data{};
    assert(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    SOCKET socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(socket != INVALID_SOCKET);
    assert(ResolveWsaRecvMsg(socket, &receiveMessage) == 0);
    assert(receiveMessage != nullptr);
    assert(ResolveWsaSendMsg(socket, &sendMessage) == 0);
    assert(sendMessage != nullptr);
    closesocket(socket);
    WSACleanup();
}

void TestSocks5UdpAssociateReplyParser() {
    using namespace furious::wfp::broker;
    Socks5UdpAssociateReplyView view{};
    const std::uint8_t ipv4Reply[] = {
        0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x12, 0x34
    };
    assert(ParseSocks5UdpAssociateReply(ipv4Reply, sizeof(ipv4Reply), view) ==
        Socks5UdpAssociateReplyResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Ipv4);
    assert(view.addressLength == 4 && view.port == 0x1234);
    assert(view.address[0] == 127 && view.address[3] == 1);

    const std::uint8_t ipv6Reply[] = {
        0x05, 0x00, 0x00, 0x04,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x23, 0x45
    };
    assert(ParseSocks5UdpAssociateReply(ipv6Reply, sizeof(ipv6Reply), view) ==
        Socks5UdpAssociateReplyResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Ipv6);
    assert(view.addressLength == 16 && view.port == 0x2345);

    const std::uint8_t domainReply[] = {
        0x05, 0x00, 0x00, 0x03, 0x09,
        'l', 'o', 'c', 'a', 'l', 'h', 'o', 's', 't', 0x01, 0xBB
    };
    assert(ParseSocks5UdpAssociateReply(domainReply, sizeof(domainReply), view) ==
        Socks5UdpAssociateReplyResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Domain);
    assert(view.addressLength == 9 && view.port == 443);

    std::vector<std::uint8_t> rejected(ipv4Reply, ipv4Reply + sizeof(ipv4Reply));
    rejected[1] = 0x05;
    assert(ParseSocks5UdpAssociateReply(rejected.data(), rejected.size(), view) ==
        Socks5UdpAssociateReplyResult::ServerRejected);
    assert(view.replyCode == 0x05);
    std::vector<std::uint8_t> invalidReserved(ipv4Reply, ipv4Reply + sizeof(ipv4Reply));
    invalidReserved[2] = 1;
    assert(ParseSocks5UdpAssociateReply(invalidReserved.data(), invalidReserved.size(), view) ==
        Socks5UdpAssociateReplyResult::InvalidReservedField);
    std::vector<std::uint8_t> invalidPort(ipv4Reply, ipv4Reply + sizeof(ipv4Reply));
    invalidPort[8] = 0;
    invalidPort[9] = 0;
    assert(ParseSocks5UdpAssociateReply(invalidPort.data(), invalidPort.size(), view) ==
        Socks5UdpAssociateReplyResult::InvalidPort);
    assert(ParseSocks5UdpAssociateReply(ipv4Reply, sizeof(ipv4Reply) - 1, view) ==
        Socks5UdpAssociateReplyResult::Truncated);
    auto trailing = std::vector<std::uint8_t>(ipv4Reply, ipv4Reply + sizeof(ipv4Reply));
    trailing.push_back(0);
    assert(ParseSocks5UdpAssociateReply(trailing.data(), trailing.size(), view) ==
        Socks5UdpAssociateReplyResult::TrailingData);
    assert(ParseSocks5UdpAssociateReply(nullptr, 0, view) ==
        Socks5UdpAssociateReplyResult::NullReply);
}

void TestSocks5UdpAssociateControlMessages() {
    using namespace furious::wfp::broker;
    Socks5UdpAssociateRequestView view{};
    const std::uint8_t ipv4Request[] = {5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
    assert(ParseSocks5UdpAssociateRequest(ipv4Request, sizeof(ipv4Request), view) ==
        Socks5UdpAssociateRequestResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Ipv4 &&
        view.addressLength == 4 && view.port == 0);
    const std::uint8_t ipv6Request[] = {5, 3, 0, 4,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1, 0x12,0x34};
    assert(ParseSocks5UdpAssociateRequest(ipv6Request, sizeof(ipv6Request), view) ==
        Socks5UdpAssociateRequestResult::Valid);
    assert(view.addressType == Socks5UdpAddressType::Ipv6 && view.port == 0x1234);
    const std::uint8_t connectRequest[] = {5, 1, 0, 1, 127,0,0,1,0,80};
    assert(ParseSocks5UdpAssociateRequest(connectRequest, sizeof(connectRequest), view) ==
        Socks5UdpAssociateRequestResult::UnsupportedCommand);
    const std::uint8_t badVersion[] = {4, 3, 0, 1, 127,0,0,1,0,53};
    assert(ParseSocks5UdpAssociateRequest(badVersion, sizeof(badVersion), view) ==
        Socks5UdpAssociateRequestResult::InvalidVersion);
    const std::uint8_t trailing[] = {5,3,0,1,127,0,0,1,0,53,0};
    assert(ParseSocks5UdpAssociateRequest(trailing, sizeof(trailing), view) ==
        Socks5UdpAssociateRequestResult::TrailingData);
    const std::uint8_t address[] = {127,0,0,1};
    std::vector<std::uint8_t> reply;
    assert(BuildSocks5UdpAssociateReply(Socks5UdpAddressType::Ipv4,
        address, sizeof(address), 40000, reply) == Socks5UdpBuildResult::Valid);
    const std::vector<std::uint8_t> expected = {5,0,0,1,127,0,0,1,0x9C,0x40};
    assert(reply == expected);
    assert(BuildSocks5UdpAssociateReply(Socks5UdpAddressType::Ipv4,
        address, sizeof(address), 0, reply) == Socks5UdpBuildResult::InvalidPort);
    assert(reply.empty());
    const std::uint8_t ipv6[] = {0x20,0x01,0x0D,0xB8,0,0,0,0,0,0,0,0,0,0,0,1};
    assert(BuildSocks5UdpAssociateReply(Socks5UdpAddressType::Ipv6,
        ipv6, sizeof(ipv6), 5353, reply) == Socks5UdpBuildResult::Valid);
    assert(reply.size() == 22 && reply[0] == 5 && reply[1] == 0 &&
        reply[3] == 4 && reply[20] == 0x14 && reply[21] == 0xE9);
    const std::uint8_t domain[] = {'r','e','l','a','y','.','l','o','c','a','l'};
    assert(BuildSocks5UdpAssociateReply(Socks5UdpAddressType::Domain,
        domain, sizeof(domain), 40000, reply) == Socks5UdpBuildResult::Valid);
    assert(reply.size() == 18 && reply[3] == 3 && reply[4] == sizeof(domain));
    std::uint8_t tooLongDomain[256]{};
    assert(BuildSocks5UdpAssociateReply(Socks5UdpAddressType::Domain,
        tooLongDomain, sizeof(tooLongDomain), 40000, reply) ==
        Socks5UdpBuildResult::InvalidAddressLength);
    assert(reply.empty());
    assert(BuildSocks5UdpAssociateReply(static_cast<Socks5UdpAddressType>(0x7F),
        address, sizeof(address), 40000, reply) == Socks5UdpBuildResult::InvalidAddressType);
    assert(reply.empty());
}

void TestBrokerServerLifecycle();
void TestBrokerConcurrentStartStopIsSerialized();
void TestBrokerStopsWhileAcceptingConnections();

int main() {
    TestSocks5UdpParser();
    TestSocks5UdpAssociationLifecycle();
    TestSocks5UdpAssociationManagerLimitsAndExpiry();
    TestSocks5UdpSocketOwnership();
    TestSocks5UdpAssociateReplyParser();
    TestSocks5UdpAssociationClientHandshake();
    TestSocks5UdpRelayTransportLoopback();
    TestSocks5UdpFlowRelayBridge();
    TestWfpUdpRedirectContextDecode();
    TestWfpUdpFlowManager();
    TestWfpUdpMessageReceive();
    TestWfpUdpRedirectRecordAncillaryData();
    TestSocks5UdpAssociateControlMessages();
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
