#pragma once
#include "WfpSocks5Udp.h"
namespace furious::wfp::broker {
enum class Socks5UdpAssociateReplyResult {
    Valid,
    NullReply,
    Truncated,
    InvalidVersion,
    ServerRejected,
    InvalidReservedField,
    UnsupportedAddressType,
    EmptyDomain,
    InvalidPort,
    TrailingData
};
struct Socks5UdpAssociateReplyView final {
    Socks5UdpAddressType addressType = Socks5UdpAddressType::Ipv4;
    const std::uint8_t* address = nullptr;
    std::size_t addressLength = 0;
    std::uint16_t port = 0; // Host byte order.
    std::uint8_t replyCode = 0;
};
enum class Socks5UdpAssociateRequestResult {
    Valid, NullRequest, Truncated, InvalidVersion, UnsupportedCommand,
    InvalidReservedField, UnsupportedAddressType, EmptyDomain, TrailingData
};
struct Socks5UdpAssociateRequestView final {
    Socks5UdpAddressType addressType = Socks5UdpAddressType::Ipv4;
    const std::uint8_t* address = nullptr;
    std::size_t addressLength = 0;
    std::uint16_t port = 0; // Host byte order; zero asks the server to learn it.
};
// Parses the SOCKS5 command request (VER, CMD=UDP ASSOCIATE, RSV, ATYP,
// DST.ADDR, DST.PORT). The returned address is a non-owning view.
Socks5UdpAssociateRequestResult ParseSocks5UdpAssociateRequest(
    const std::uint8_t* request, std::size_t requestLength,
    Socks5UdpAssociateRequestView& output) noexcept;
// Parses the successful UDP ASSOCIATE response (VER, REP, RSV, ATYP,
// BND.ADDR, BND.PORT). Address bytes are a non-owning view.
Socks5UdpAssociateReplyResult ParseSocks5UdpAssociateReply(
    const std::uint8_t* reply, std::size_t replyLength,
    Socks5UdpAssociateReplyView& output) noexcept;
// Builds a successful UDP ASSOCIATE reply using the actual bound relay endpoint.
Socks5UdpBuildResult BuildSocks5UdpAssociateReply(
    Socks5UdpAddressType addressType, const std::uint8_t* address,
    std::size_t addressLength, std::uint16_t port,
    std::vector<std::uint8_t>& output) noexcept;
}
