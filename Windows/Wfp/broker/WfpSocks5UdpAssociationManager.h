#pragma once

#include "WfpSocks5UdpAssociation.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace furious::wfp::broker {

enum class Socks5UdpAssociationOpenResult {
    Opened,
    InvalidId,
    InvalidParameters,
    DuplicateId,
    AssociationLimitReached,
    PerPeerLimitReached,
    AllocationFailure
};

// Bounded registry. The TCP control-session owner must Close() on disconnect.
class Socks5UdpAssociationManager final {
public:
    explicit Socks5UdpAssociationManager(
        std::size_t maximumAssociations = 128,
        std::size_t maximumAssociationsPerPeer = 8) noexcept;

    Socks5UdpAssociationManager(const Socks5UdpAssociationManager&) = delete;
    Socks5UdpAssociationManager& operator=(const Socks5UdpAssociationManager&) = delete;

    Socks5UdpAssociationOpenResult Open(
        std::uint64_t id,
        const Socks5UdpEndpoint& controlPeer,
        std::uint16_t requestedClientPort,
        std::chrono::milliseconds idleTimeout,
        std::size_t maximumDatagramLength,
        Socks5UdpAssociation::TimePoint now) noexcept;

    Socks5UdpAssociationResult AuthorizeClientDatagram(
        std::uint64_t id,
        const Socks5UdpEndpoint& source,
        std::size_t datagramLength,
        Socks5UdpAssociation::TimePoint now) noexcept;

    bool Close(std::uint64_t id) noexcept;
    std::size_t SweepExpired(Socks5UdpAssociation::TimePoint now) noexcept;
    std::size_t ActiveCount() const noexcept;
    std::size_t MaximumAssociations() const noexcept;
    std::size_t MaximumAssociationsPerPeer() const noexcept;

private:
    struct Entry final {
        std::uint64_t id = 0;
        Socks5UdpEndpoint controlPeer{};
        Socks5UdpAssociation association{};
    };

    bool SamePeerAddress(
        const Socks5UdpEndpoint& a,
        const Socks5UdpEndpoint& b) const noexcept;

    const std::size_t maximumAssociations_;
    const std::size_t maximumAssociationsPerPeer_;
    std::vector<Entry> entries_;
};

} // namespace furious::wfp::broker
