#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace furious::wfp::broker {

// RFC 1928 UDP request address types.
enum class Socks5UdpAddressType : std::uint8_t {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04
};

enum class Socks5UdpBuildResult {
    Valid,
    NullAddress,
    InvalidAddressType,
    InvalidAddressLength,
    EmptyDomain,
    InvalidPort,
    NullPayload,
    DatagramTooLarge,
    AllocationFailure
};

constexpr std::size_t kMaximumSocks5UdpDatagramSize = 65507;

enum class Socks5UdpParseResult {
    Valid,
    NullDatagram,
    Truncated,
    InvalidReservedField,
    FragmentationUnsupported,
    UnsupportedAddressType,
    EmptyDomain,
    InvalidPort
};

// Non-owning view. All pointers refer to the caller-owned datagram and remain
// valid only while that input buffer remains alive and unchanged.
struct Socks5UdpDatagramView final {
    Socks5UdpAddressType addressType = Socks5UdpAddressType::Ipv4;
    const std::uint8_t* address = nullptr;
    std::size_t addressLength = 0;
    std::uint16_t port = 0; // Host byte order.
    const std::uint8_t* payload = nullptr;
    std::size_t payloadLength = 0;
};

// Builds one complete SOCKS5 UDP datagram. The output is cleared on failure.
// maximumDatagramLength can impose a stricter per-association size cap.
Socks5UdpBuildResult BuildSocks5UdpDatagram(
    Socks5UdpAddressType addressType,
    const std::uint8_t* address,
    std::size_t addressLength,
    std::uint16_t port,
    const std::uint8_t* payload,
    std::size_t payloadLength,
    std::vector<std::uint8_t>& output,
    std::size_t maximumDatagramLength = kMaximumSocks5UdpDatagramSize) noexcept;

// Parses one complete SOCKS5 UDP datagram (RSV, FRAG, ATYP, DST.ADDR,
// DST.PORT, DATA). Fragmented datagrams are rejected until reassembly exists.
// No allocation, DNS lookup, socket operation, or packet mutation occurs.
Socks5UdpParseResult ParseSocks5UdpDatagram(
    const std::uint8_t* datagram,
    std::size_t datagramLength,
    Socks5UdpDatagramView& output) noexcept;

} // namespace furious::wfp::broker
