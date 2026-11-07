#include "../WfpSocks5Udp.h"
#include "../WfpSocks5UdpControl.h"
#include "../WfpSocks5UdpAssociation.h"
#include "../WfpSocks5UdpAssociationManager.h"

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <vector>

using namespace furious::wfp::broker;

namespace {
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
    TestDatagramRoundTrips();
    TestDatagramRejectsMalformedInput();
    TestAssociateControlMessages();
    TestAssociationSourcePinningAndExpiry();
    TestAssociationManagerQuotasAndCleanup();
    return 0;
}
