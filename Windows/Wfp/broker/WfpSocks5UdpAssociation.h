#pragma once
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
namespace furious::wfp::broker {
enum class Socks5UdpEndpointFamily : std::uint8_t { Ipv4, Ipv6 };
struct Socks5UdpEndpoint final {
    Socks5UdpEndpointFamily family = Socks5UdpEndpointFamily::Ipv4;
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port = 0;
};
enum class Socks5UdpAssociationResult {
    Accepted, Inactive, InvalidSourceEndpoint, SourceAddressMismatch,
    SourcePortMismatch, DatagramTooLarge
};
// Pure state guard: no DNS, socket I/O, or packet forwarding.
class Socks5UdpAssociation final {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    bool Start(const Socks5UdpEndpoint& controlPeer, std::uint16_t requestedClientPort,
        std::chrono::milliseconds idleTimeout, std::size_t maximumDatagramLength,
        TimePoint now) noexcept;
    Socks5UdpAssociationResult AuthorizeClientDatagram(
        const Socks5UdpEndpoint& source, std::size_t datagramLength, TimePoint now) noexcept;
    void OnControlClosed() noexcept;
    void Close() noexcept;
    bool IsActive(TimePoint now) const noexcept;
    bool HasBoundClient() const noexcept;
    const Socks5UdpEndpoint& BoundClient() const noexcept;
    std::size_t MaximumDatagramLength() const noexcept;
private:
    bool IsUsableUnicastAddress(const Socks5UdpEndpoint&) const noexcept;
    bool SameAddress(const Socks5UdpEndpoint&, const Socks5UdpEndpoint&) const noexcept;
    Socks5UdpEndpoint peer_{};
    Socks5UdpEndpoint client_{};
    std::uint16_t requestedPort_ = 0;
    std::chrono::milliseconds idleTimeout_{0};
    std::size_t maximumDatagramLength_ = 0;
    TimePoint lastActivity_{};
    bool active_ = false;
    bool clientBound_ = false;
};
}
