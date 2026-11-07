#include "WfpSocks5UdpAssociation.h"
#include "WfpSocks5Udp.h"
namespace furious::wfp::broker {
bool Socks5UdpAssociation::SameAddress(const Socks5UdpEndpoint& a,
    const Socks5UdpEndpoint& b) const noexcept {
    if (a.family != b.family) return false;
    const std::size_t n = a.family == Socks5UdpEndpointFamily::Ipv4 ? 4 :
        (a.family == Socks5UdpEndpointFamily::Ipv6 ? 16 : 0);
    if (n == 0) return false;
    for (std::size_t i=0; i<n; ++i) if (a.address[i] != b.address[i]) return false;
    return true;
}
bool Socks5UdpAssociation::Start(const Socks5UdpEndpoint& peer,
    std::uint16_t requestedPort, std::chrono::milliseconds timeout,
    std::size_t maximumLength, TimePoint now) noexcept {
    Close();
    if ((peer.family != Socks5UdpEndpointFamily::Ipv4 &&
         peer.family != Socks5UdpEndpointFamily::Ipv6) ||
        timeout.count() <= 0 || maximumLength == 0 ||
        maximumLength > kMaximumSocks5UdpDatagramSize) return false;
    peer_ = peer;
    peer_.port = 0; // TCP control port is not the UDP source port.
    requestedPort_ = requestedPort;
    idleTimeout_ = timeout;
    maximumDatagramLength_ = maximumLength;
    lastActivity_ = now;
    active_ = true;
    return true;
}
Socks5UdpAssociationResult Socks5UdpAssociation::AuthorizeClientDatagram(
    const Socks5UdpEndpoint& source, std::size_t length, TimePoint now) noexcept {
    if (!IsActive(now)) { Close(); return Socks5UdpAssociationResult::Inactive; }
    if ((source.family != Socks5UdpEndpointFamily::Ipv4 &&
         source.family != Socks5UdpEndpointFamily::Ipv6) || source.port == 0)
        return Socks5UdpAssociationResult::InvalidSourceEndpoint;
    if (!SameAddress(source, peer_))
        return Socks5UdpAssociationResult::SourceAddressMismatch;
    if (length == 0 || length > maximumDatagramLength_)
        return Socks5UdpAssociationResult::DatagramTooLarge;
    if (requestedPort_ != 0 && source.port != requestedPort_)
        return Socks5UdpAssociationResult::SourcePortMismatch;
    if (clientBound_ && source.port != client_.port)
        return Socks5UdpAssociationResult::SourcePortMismatch;
    if (!clientBound_) { client_ = source; clientBound_ = true; }
    lastActivity_ = now;
    return Socks5UdpAssociationResult::Accepted;
}
void Socks5UdpAssociation::OnControlClosed() noexcept { Close(); }
void Socks5UdpAssociation::Close() noexcept {
    peer_ = Socks5UdpEndpoint{}; client_ = Socks5UdpEndpoint{};
    requestedPort_ = 0; idleTimeout_ = std::chrono::milliseconds{0};
    maximumDatagramLength_ = 0; lastActivity_ = TimePoint{};
    active_ = false; clientBound_ = false;
}
bool Socks5UdpAssociation::IsActive(TimePoint now) const noexcept {
    return active_ && now >= lastActivity_ && now-lastActivity_ < idleTimeout_;
}
bool Socks5UdpAssociation::HasBoundClient() const noexcept { return active_ && clientBound_; }
const Socks5UdpEndpoint& Socks5UdpAssociation::BoundClient() const noexcept { return client_; }
std::size_t Socks5UdpAssociation::MaximumDatagramLength() const noexcept {
    return active_ ? maximumDatagramLength_ : 0;
}
}
