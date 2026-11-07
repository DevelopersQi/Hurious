#include "../WfpTcpRedirect.h"
#include "../WfpSocks5Udp.h"
#include "../WfpSocks5UdpAssociation.h"
#include "../WfpSocks5UdpAssociationManager.h"
#include "../WfpSocks5UdpSocket.h"
#include "../WfpSocks5UdpRedirectRecord.h"
#include "../WfpSocks5UdpControl.h"
#include <chrono>
#include <atomic>
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

void TestWfpUdpRedirectRecordAncillaryData() {
    using namespace furious::wfp::broker;
    std::vector<std::uint8_t> extracted;
    WSAMSG message{};
    assert(ExtractWfpUdpRedirectRecord(message, extracted) ==
        WfpUdpRedirectRecordResult::NotPresent);
    assert(extracted.empty());

    const std::uint8_t record[] = {0x10, 0x20, 0x30, 0x40, 0x50};
    std::vector<char> controlBuffer(WSA_CMSG_SPACE(sizeof(record)));
    message.Control.buf = controlBuffer.data();
    message.Control.len = static_cast<ULONG>(controlBuffer.size());
    WSACMSGHDR* header = WSA_CMSG_FIRSTHDR(&message);
    assert(header != nullptr);
    header->cmsg_level = IPPROTO_IP;
    header->cmsg_type = IP_CONNECTION_REDIRECT_RECORD;
    header->cmsg_len = WSA_CMSG_LEN(sizeof(record));
    std::memcpy(WSA_CMSG_DATA(header), record, sizeof(record));
    assert(ExtractWfpUdpRedirectRecord(message, extracted) ==
        WfpUdpRedirectRecordResult::Present);
    assert(extracted.size() == sizeof(record));
    assert(std::memcmp(extracted.data(), record, sizeof(record)) == 0);

    header->cmsg_len = 0;
    assert(ExtractWfpUdpRedirectRecord(message, extracted) ==
        WfpUdpRedirectRecordResult::InvalidMessage);
    assert(extracted.empty());

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
