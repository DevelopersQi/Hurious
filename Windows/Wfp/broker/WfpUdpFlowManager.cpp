#include "WfpUdpFlowManager.h"

#include <ws2tcpip.h>

#include <cstring>
#include <utility>

namespace furious::wfp::broker {

WfpUdpFlowManager::WfpUdpFlowManager(
    std::size_t maximumFlows,
    std::size_t maximumFlowsPerProcess,
    std::chrono::milliseconds idleTimeout) noexcept
    : maximumFlows_(maximumFlows),
      maximumFlowsPerProcess_(maximumFlowsPerProcess),
      idleTimeout_(idleTimeout) {
}

bool WfpUdpFlowManager::IsValidSourceEndpoint(
    const sockaddr* endpoint,
    int endpointLength) noexcept {
    if (endpoint == nullptr) return false;
    if (endpoint->sa_family == AF_INET) {
        if (endpointLength != static_cast<int>(sizeof(sockaddr_in))) return false;
        const auto* address = reinterpret_cast<const sockaddr_in*>(endpoint);
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&address->sin_addr);
        if (address->sin_port == 0 || bytes[0] == 0 || bytes[0] >= 224) return false;
        return true;
    }
    if (endpoint->sa_family == AF_INET6) {
        if (endpointLength != static_cast<int>(sizeof(sockaddr_in6))) return false;
        const auto* address = reinterpret_cast<const sockaddr_in6*>(endpoint);
        if (address->sin6_port == 0) return false;
        const auto* bytes = address->sin6_addr.u.Byte;
        const bool linkLocal = bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80;
        // Scope IDs identify the interface zone for link-local addresses only.
        // Require one for link-local endpoints and reject stray zones on global
        // or loopback endpoints so aliases cannot create parallel flow identities.
        if (linkLocal != (address->sin6_scope_id != 0)) return false;
        bool unspecified = true;
        for (std::uint8_t byte : address->sin6_addr.u.Byte) {
            if (byte != 0) { unspecified = false; break; }
        }
        return !unspecified && address->sin6_addr.u.Byte[0] != 0xFF;
    }
    return false;
}

bool WfpUdpFlowManager::SameSourceEndpoint(
    const sockaddr_storage& a,
    int aLength,
    const sockaddr* b,
    int bLength) noexcept {
    if (b == nullptr || a.ss_family != b->sa_family) return false;
    if (a.ss_family == AF_INET) {
        if (aLength < static_cast<int>(sizeof(sockaddr_in)) ||
            bLength < static_cast<int>(sizeof(sockaddr_in))) return false;
        const auto* left = reinterpret_cast<const sockaddr_in*>(&a);
        const auto* right = reinterpret_cast<const sockaddr_in*>(b);
        return left->sin_port == right->sin_port &&
            left->sin_addr.s_addr == right->sin_addr.s_addr;
    }
    if (a.ss_family == AF_INET6) {
        if (aLength < static_cast<int>(sizeof(sockaddr_in6)) ||
            bLength < static_cast<int>(sizeof(sockaddr_in6))) return false;
        const auto* left = reinterpret_cast<const sockaddr_in6*>(&a);
        const auto* right = reinterpret_cast<const sockaddr_in6*>(b);
        return left->sin6_port == right->sin6_port &&
            left->sin6_scope_id == right->sin6_scope_id &&
            std::memcmp(&left->sin6_addr, &right->sin6_addr,
                sizeof(left->sin6_addr)) == 0;
    }
    return false;
}

bool WfpUdpFlowManager::IsValidRedirectContext(
    const FURIOUS_WFP_REDIRECT_CONTEXT& context,
    int sourceAddressFamily) noexcept {
    if (!furious::wfp::redirect::IsValidRedirectContext(context) ||
        context.Protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_UDP) {
        return false;
    }

    if ((sourceAddressFamily == AF_INET &&
            context.AddressFamily != FURIOUS_WFP_REDIRECT_FAMILY_V4) ||
        (sourceAddressFamily == AF_INET6 &&
            context.AddressFamily != FURIOUS_WFP_REDIRECT_FAMILY_V6)) {
        return false;
    }

    if (context.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4) {
        const auto* address = context.OriginalAddress;
        if (address[0] == 0 || address[0] >= 224) return false;
        return true;
    }

    bool unspecified = true;
    for (std::uint8_t byte : context.OriginalAddress) {
        if (byte != 0) { unspecified = false; break; }
    }
    return !unspecified && context.OriginalAddress[0] != 0xFF;
}

bool WfpUdpFlowManager::SameFlowIdentity(
    const Entry& entry,
    const FURIOUS_WFP_REDIRECT_CONTEXT& context,
    const std::vector<std::uint8_t>& redirectRecord) noexcept {
    return std::memcmp(&entry.redirectContext, &context, sizeof(context)) == 0 &&
        entry.redirectRecord == redirectRecord;
}

bool WfpUdpFlowManager::IsExpired(
    const Entry& entry,
    TimePoint now) const noexcept {
    return now < entry.lastActivity || now - entry.lastActivity >= idleTimeout_;
}

std::uint64_t WfpUdpFlowManager::AllocateId() noexcept {
    for (std::size_t attempt = 0; attempt <= entries_.size(); ++attempt) {
        std::uint64_t candidate = nextId_++;
        if (nextId_ == 0) nextId_ = 1;
        if (candidate == 0) continue;
        bool used = false;
        for (const auto& entry : entries_) {
            if (entry.id == candidate) { used = true; break; }
        }
        if (!used) return candidate;
    }
    return 0;
}

WfpUdpFlowCreateResult WfpUdpFlowManager::RegisterFirstDatagram(
    const sockaddr* sourceEndpoint,
    int sourceEndpointLength,
    const FURIOUS_WFP_REDIRECT_CONTEXT& redirectContext,
    const std::vector<std::uint8_t>& redirectRecord,
    TimePoint now,
    std::uint64_t& flowId) noexcept {
    flowId = 0;
    if (!IsValidSourceEndpoint(sourceEndpoint, sourceEndpointLength)) {
        return WfpUdpFlowCreateResult::InvalidSource;
    }
    if (!IsValidRedirectContext(redirectContext, sourceEndpoint->sa_family)) {
        return WfpUdpFlowCreateResult::InvalidContext;
    }
    if (redirectRecord.empty()) return WfpUdpFlowCreateResult::MissingRedirectRecord;
    if (redirectRecord.size() > kMaximumWfpUdpRedirectRecordSize) {
        return WfpUdpFlowCreateResult::RedirectRecordTooLarge;
    }
    if (maximumFlows_ == 0 || maximumFlowsPerProcess_ == 0 ||
        idleTimeout_.count() <= 0) {
        return WfpUdpFlowCreateResult::FlowLimitReached;
    }

    Entry candidate{};
    candidate.sourceEndpointLength = sourceEndpointLength;
    std::memcpy(&candidate.sourceEndpoint, sourceEndpoint,
        static_cast<std::size_t>(sourceEndpointLength));
    candidate.redirectContext = redirectContext;
    candidate.lastActivity = now;
    try {
        candidate.redirectRecord = redirectRecord;
    } catch (...) {
        return WfpUdpFlowCreateResult::AllocationFailure;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    // Expired entries are retained until the resource owner receives their
    // IDs through SweepExpired() and closes the associated sockets.
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        auto& entry = entries_[i];
        if (!SameSourceEndpoint(entry.sourceEndpoint, entry.sourceEndpointLength,
                sourceEndpoint, sourceEndpointLength)) continue;
        if (IsExpired(entry, now)) {
            flowId = entry.id;
            return WfpUdpFlowCreateResult::ExpiredFlow;
        }
        if (SameFlowIdentity(entry, redirectContext, redirectRecord)) {
            entry.lastActivity = now;
            flowId = entry.id;
            return WfpUdpFlowCreateResult::ExistingFlow;
        }
        return WfpUdpFlowCreateResult::SourceEndpointConflict;
    }

    if (entries_.size() >= maximumFlows_) {
        return WfpUdpFlowCreateResult::FlowLimitReached;
    }
    std::size_t processCount = 0;
    for (const auto& entry : entries_) {
        if (entry.redirectContext.OriginalProcessId ==
            redirectContext.OriginalProcessId) ++processCount;
    }
    if (processCount >= maximumFlowsPerProcess_) {
        return WfpUdpFlowCreateResult::PerProcessLimitReached;
    }

    candidate.id = AllocateId();
    if (candidate.id == 0) return WfpUdpFlowCreateResult::AllocationFailure;
    flowId = candidate.id;
    try {
        entries_.push_back(std::move(candidate));
    } catch (...) {
        flowId = 0;
        return WfpUdpFlowCreateResult::AllocationFailure;
    }
    return WfpUdpFlowCreateResult::Created;
}

WfpUdpFlowTouchResult WfpUdpFlowManager::Touch(
    const sockaddr* sourceEndpoint,
    int sourceEndpointLength,
    TimePoint now,
    std::uint64_t& flowId) noexcept {
    flowId = 0;
    if (!IsValidSourceEndpoint(sourceEndpoint, sourceEndpointLength)) {
        return WfpUdpFlowTouchResult::InvalidSource;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        auto& entry = entries_[i];
        if (!SameSourceEndpoint(entry.sourceEndpoint, entry.sourceEndpointLength,
                sourceEndpoint, sourceEndpointLength)) continue;
        if (IsExpired(entry, now)) {
            // Preserve the ID so the owner can close the relay before Remove().
            flowId = entry.id;
            return WfpUdpFlowTouchResult::Expired;
        }
        entry.lastActivity = now;
        flowId = entry.id;
        return WfpUdpFlowTouchResult::Found;
    }
    return WfpUdpFlowTouchResult::NotFound;
}

bool WfpUdpFlowManager::IsActive(
    std::uint64_t flowId,
    TimePoint now) const noexcept {
    if (flowId == 0) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.id == flowId) {
            return !IsExpired(entry, now);
        }
    }
    return false;
}

bool WfpUdpFlowManager::GetSnapshot(
    std::uint64_t flowId,
    WfpUdpFlowSnapshot& output) const noexcept {
    output = WfpUdpFlowSnapshot{};
    if (flowId == 0) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries_) {
        if (entry.id != flowId) continue;
        output.id = entry.id;
        output.sourceEndpoint = entry.sourceEndpoint;
        output.sourceEndpointLength = entry.sourceEndpointLength;
        output.redirectContext = entry.redirectContext;
        output.lastActivity = entry.lastActivity;
        try {
            output.redirectRecord = entry.redirectRecord;
        } catch (...) {
            output = WfpUdpFlowSnapshot{};
            return false;
        }
        return true;
    }
    return false;
}

bool WfpUdpFlowManager::Remove(std::uint64_t flowId) noexcept {
    if (flowId == 0) return false;
    std::lock_guard<std::mutex> lock(mutex_);
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].id != flowId) continue;
        entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(i));
        return true;
    }
    return false;
}

bool WfpUdpFlowManager::FindExpired(
    TimePoint now, std::uint64_t& expiredFlowId) const noexcept {
    expiredFlowId = 0;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& entry : entries_) {
        if (!IsExpired(entry, now)) continue;
        expiredFlowId = entry.id;
        return true;
    }
    return false;
}

bool WfpUdpFlowManager::FindExpiredFrom(
    TimePoint now, std::size_t& scanIndex,
    std::uint64_t& expiredFlowId) const noexcept {
    expiredFlowId = 0;
    std::lock_guard<std::mutex> lock(mutex_);
    if (scanIndex > entries_.size()) scanIndex = entries_.size();
    for (std::size_t index = scanIndex; index < entries_.size(); ++index) {
        if (!IsExpired(entries_[index], now)) continue;
        scanIndex = index;
        expiredFlowId = entries_[index].id;
        return true;
    }
    scanIndex = entries_.size();
    return false;
}

void WfpUdpFlowManager::Clear() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
}

std::size_t WfpUdpFlowManager::SweepExpired(TimePoint now) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    std::size_t expired = 0;
    for (const auto& entry : entries_) {
        if (IsExpired(entry, now)) ++expired;
    }
    return expired;
}

std::size_t WfpUdpFlowManager::SweepExpired(
    TimePoint now,
    std::vector<std::uint64_t>& expiredFlowIds) noexcept {
    expiredFlowIds.clear();
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        expiredFlowIds.reserve(entries_.size());
    } catch (...) {
        return 0;
    }
    // Do not erase here: the caller still owns sockets and control connections.
    // Keep IDs discoverable until the owner closes resources and calls Remove().
    for (const auto& entry : entries_) {
        if (IsExpired(entry, now)) expiredFlowIds.push_back(entry.id);
    }
    return expiredFlowIds.size();
}

std::size_t WfpUdpFlowManager::ActiveCount() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
}

std::size_t WfpUdpFlowManager::MaximumFlows() const noexcept {
    return maximumFlows_;
}

std::size_t WfpUdpFlowManager::MaximumFlowsPerProcess() const noexcept {
    return maximumFlowsPerProcess_;
}

} // namespace furious::wfp::broker
