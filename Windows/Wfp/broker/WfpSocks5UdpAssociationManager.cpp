#include "WfpSocks5UdpAssociationManager.h"

namespace furious::wfp::broker {

Socks5UdpAssociationManager::Socks5UdpAssociationManager(
    std::size_t maximumAssociations,
    std::size_t maximumAssociationsPerPeer) noexcept
    : maximumAssociations_(maximumAssociations),
      maximumAssociationsPerPeer_(maximumAssociationsPerPeer) {
}

bool Socks5UdpAssociationManager::SamePeerAddress(
    const Socks5UdpEndpoint& a,
    const Socks5UdpEndpoint& b) const noexcept {
    if (a.family != b.family) return false;
    const std::size_t length =
        a.family == Socks5UdpEndpointFamily::Ipv4 ? 4 :
        a.family == Socks5UdpEndpointFamily::Ipv6 ? 16 : 0;
    if (length == 0) return false;
    for (std::size_t i = 0; i < length; ++i) {
        if (a.address[i] != b.address[i]) return false;
    }
    return true;
}

Socks5UdpAssociationOpenResult Socks5UdpAssociationManager::Open(
    std::uint64_t id,
    const Socks5UdpEndpoint& controlPeer,
    std::uint16_t requestedClientPort,
    std::chrono::milliseconds idleTimeout,
    std::size_t maximumDatagramLength,
    Socks5UdpAssociation::TimePoint now) noexcept {
    if (id == 0) return Socks5UdpAssociationOpenResult::InvalidId;
    if (maximumAssociations_ == 0 || maximumAssociationsPerPeer_ == 0) {
        return Socks5UdpAssociationOpenResult::InvalidParameters;
    }

    Socks5UdpAssociation candidate;
    if (!candidate.Start(controlPeer, requestedClientPort,
            idleTimeout, maximumDatagramLength, now)) {
        return Socks5UdpAssociationOpenResult::InvalidParameters;
    }
    for (const auto& entry : entries_) {
        if (entry.id == id) return Socks5UdpAssociationOpenResult::DuplicateId;
    }
    if (entries_.size() >= maximumAssociations_) {
        return Socks5UdpAssociationOpenResult::AssociationLimitReached;
    }

    std::size_t peerCount = 0;
    for (const auto& entry : entries_) {
        // Per-peer quotas key on the TCP peer IP, not its ephemeral TCP port.
        if (SamePeerAddress(entry.controlPeer, controlPeer)) ++peerCount;
    }
    if (peerCount >= maximumAssociationsPerPeer_) {
        return Socks5UdpAssociationOpenResult::PerPeerLimitReached;
    }

    Entry entry{};
    entry.id = id;
    entry.controlPeer = controlPeer;
    entry.association = candidate;
    try {
        entries_.push_back(entry);
    } catch (...) {
        return Socks5UdpAssociationOpenResult::AllocationFailure;
    }
    return Socks5UdpAssociationOpenResult::Opened;
}

Socks5UdpAssociationResult Socks5UdpAssociationManager::AuthorizeClientDatagram(
    std::uint64_t id,
    const Socks5UdpEndpoint& source,
    std::size_t datagramLength,
    Socks5UdpAssociation::TimePoint now) noexcept {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].id != id) continue;
        const auto result = entries_[i].association.AuthorizeClientDatagram(
            source, datagramLength, now);
        if (result == Socks5UdpAssociationResult::Inactive) {
            entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
        }
        return result;
    }
    return Socks5UdpAssociationResult::Inactive;
}

bool Socks5UdpAssociationManager::Close(std::uint64_t id) noexcept {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].id != id) continue;
        entries_[i].association.OnControlClosed();
        entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
        return true;
    }
    return false;
}

std::size_t Socks5UdpAssociationManager::SweepExpired(
    Socks5UdpAssociation::TimePoint now) noexcept {
    std::size_t removed = 0;
    for (std::size_t i = 0; i < entries_.size();) {
        if (!entries_[i].association.IsActive(now)) {
            entries_[i].association.Close();
            entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
            ++removed;
        } else {
            ++i;
        }
    }
    return removed;
}

std::size_t Socks5UdpAssociationManager::ActiveCount() const noexcept {
    return entries_.size();
}

std::size_t Socks5UdpAssociationManager::MaximumAssociations() const noexcept {
    return maximumAssociations_;
}

std::size_t Socks5UdpAssociationManager::MaximumAssociationsPerPeer() const noexcept {
    return maximumAssociationsPerPeer_;
}

} // namespace furious::wfp::broker
