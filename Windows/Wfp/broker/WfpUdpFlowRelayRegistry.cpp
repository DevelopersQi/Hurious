#include "WfpUdpFlowRelayRegistry.h"
#include <limits>

#include <cstring>
#include <new>
#include <ws2tcpip.h>

namespace furious::wfp::broker {

WfpUdpFlowRelayRegistry::WfpUdpFlowRelayRegistry(
    std::size_t maximumFlows,
    std::size_t maximumFlowsPerProcess,
    std::chrono::milliseconds idleTimeout) noexcept
    : flows_(maximumFlows, maximumFlowsPerProcess, idleTimeout) {
}

WfpUdpFlowRelayRegistry::~WfpUdpFlowRelayRegistry() {
    CloseAll();
}

bool WfpUdpFlowRelayRegistry::Configure(
    const sockaddr* socksAddress, int socksAddressLength,
    DWORD timeoutMilliseconds, ActiveSocketRegister registerSocket,
    ActiveSocketUnregister unregisterSocket, void* callbackContext) noexcept {
    if (socksAddress == nullptr || timeoutMilliseconds == 0 ||
        ((registerSocket == nullptr) != (unregisterSocket == nullptr)) ||
        !relays_.empty()) return false;

    int expectedLength = 0;
    if (socksAddress->sa_family == AF_INET) {
        expectedLength = sizeof(sockaddr_in);
        const auto* value = reinterpret_cast<const sockaddr_in*>(socksAddress);
        if (socksAddressLength != expectedLength ||
            (ntohl(value->sin_addr.s_addr) >> 24) != 127 ||
            value->sin_port == 0) return false;
    } else if (socksAddress->sa_family == AF_INET6) {
        expectedLength = sizeof(sockaddr_in6);
        const auto* value = reinterpret_cast<const sockaddr_in6*>(socksAddress);
        if (socksAddressLength != expectedLength ||
            !IN6_IS_ADDR_LOOPBACK(&value->sin6_addr) ||
            value->sin6_port == 0) return false;
    } else {
        return false;
    }

    std::memset(&socksAddress_, 0, sizeof(socksAddress_));
    std::memcpy(&socksAddress_, socksAddress, static_cast<std::size_t>(expectedLength));
    socksAddressLength_ = expectedLength;
    timeoutMilliseconds_ = timeoutMilliseconds;
    registerSocket_ = registerSocket;
    unregisterSocket_ = unregisterSocket;
    callbackContext_ = callbackContext;
    return true;
}

WfpUdpFlowRelayRegistryResult WfpUdpFlowRelayRegistry::ProcessClientDatagram(
    const WfpUdpReceivedMessage& message, const std::uint8_t* payload, TimePoint now,
    std::uint64_t* outputFlowId, int* errorCode) noexcept {
    if (outputFlowId) *outputFlowId = 0;
    if (errorCode) *errorCode = 0;
    int localErrorCode = 0;
    int* ioErrorCode = errorCode != nullptr ? errorCode : &localErrorCode;
    if (socksAddressLength_ == 0) return WfpUdpFlowRelayRegistryResult::NotConfigured;
    if (message.payloadLength > 65507 ||
        (message.payloadLength != 0 && payload == nullptr) ||
        message.sourceAddressLength == 0) {
        return WfpUdpFlowRelayRegistryResult::InvalidMessage;
    }

    std::uint64_t flowId = 0;
    auto touch = flows_.Touch(
        reinterpret_cast<const sockaddr*>(&message.sourceAddress),
        message.sourceAddressLength, now, flowId);
    if (touch == WfpUdpFlowTouchResult::InvalidSource)
        return WfpUdpFlowRelayRegistryResult::InvalidMessage;
    if (touch == WfpUdpFlowTouchResult::Expired) {
        CloseFlow(flowId);
        flowId = 0;
    }

    // A redirected UDP socket may be reused for another destination. When
    // WFP supplies first-packet metadata again, never silently keep routing
    // that datagram through the old destination-bound relay.
    if (touch == WfpUdpFlowTouchResult::Found &&
        (!message.redirectRecord.empty() || !message.redirectContext.empty())) {
        if (message.redirectRecord.empty() || message.redirectContext.empty()) {
            // Do not let malformed metadata refresh a live flow's idle lease.
            // The source endpoint may have been reused for a different target;
            // without a complete identity, fail closed and release its relay.
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::InvalidRedirectMetadata;
        }
        FURIOUS_WFP_REDIRECT_CONTEXT incomingContext{};
        if (DecodeWfpUdpRedirectContext(message.redirectContext, incomingContext) !=
            WfpUdpRedirectContextDecodeResult::Decoded) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::InvalidRedirectMetadata;
        }
        WfpUdpFlowSnapshot existingSnapshot{};
        const bool snapshotAvailable = flows_.GetSnapshot(flowId, existingSnapshot);
        const bool sameIdentity = snapshotAvailable &&
            std::memcmp(&existingSnapshot.redirectContext, &incomingContext,
                sizeof(incomingContext)) == 0 &&
            existingSnapshot.redirectRecord == message.redirectRecord;
        if (!sameIdentity) {
            CloseFlow(flowId);
            flowId = 0;
            touch = WfpUdpFlowTouchResult::NotFound;
        }
    }

    auto found = relays_.find(flowId);
    if (touch == WfpUdpFlowTouchResult::Found) {
        if (found == relays_.end()) {
            // The flow identity must not outlive any associated queue state.
            // CloseFlow also removes stale pending/outbound queues if the
            // registry was left partially populated by an earlier failure.
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::FlowNotFound;
        }
        auto pending = pendingDatagrams_.find(flowId);
        if (pending != pendingDatagrams_.end()) {
            if (!QueuePendingDatagram(flowId, payload, message.payloadLength)) {
                CloseFlow(flowId);
                return WfpUdpFlowRelayRegistryResult::PendingQueueFull;
            }
            if (outputFlowId) *outputFlowId = flowId;
            return WfpUdpFlowRelayRegistryResult::Pending;
        }
    } else {
        if (message.redirectRecord.empty() || message.redirectContext.empty())
            return WfpUdpFlowRelayRegistryResult::MissingRedirectMetadata;
        FURIOUS_WFP_REDIRECT_CONTEXT context{};
        if (DecodeWfpUdpRedirectContext(message.redirectContext, context) !=
            WfpUdpRedirectContextDecodeResult::Decoded) {
            return WfpUdpFlowRelayRegistryResult::InvalidRedirectMetadata;
        }

        auto create = flows_.RegisterFirstDatagram(
            reinterpret_cast<const sockaddr*>(&message.sourceAddress),
            message.sourceAddressLength, context, message.redirectRecord, now, flowId);
        if (create == WfpUdpFlowCreateResult::ExpiredFlow) {
            CloseFlow(flowId);
            create = flows_.RegisterFirstDatagram(
                reinterpret_cast<const sockaddr*>(&message.sourceAddress),
                message.sourceAddressLength, context, message.redirectRecord, now, flowId);
        }
        if (create == WfpUdpFlowCreateResult::FlowLimitReached ||
            create == WfpUdpFlowCreateResult::PerProcessLimitReached) {
            return WfpUdpFlowRelayRegistryResult::FlowLimitReached;
        }
        if (create != WfpUdpFlowCreateResult::Created &&
            create != WfpUdpFlowCreateResult::ExistingFlow) {
            return WfpUdpFlowRelayRegistryResult::InvalidRedirectMetadata;
        }

        found = relays_.find(flowId);
        if (found == relays_.end()) {
            WfpUdpFlowSnapshot snapshot{};
            if (!flows_.GetSnapshot(flowId, snapshot)) {
                // GetSnapshot copies the redirect record and can fail under
                // memory pressure. Roll back the newly registered identity
                // immediately instead of leaving an unserviceable orphan flow.
                CloseFlow(flowId);
                return WfpUdpFlowRelayRegistryResult::FlowNotFound;
            }
            std::unique_ptr<WfpSocks5UdpFlowRelay> relay;
            try {
                relay = std::make_unique<WfpSocks5UdpFlowRelay>();
            } catch (...) {
                flows_.Remove(flowId);
                return WfpUdpFlowRelayRegistryResult::RelayOpenFailed;
            }
            const auto opened = relay->BeginOpen(
                reinterpret_cast<const sockaddr*>(&socksAddress_), socksAddressLength_,
                reinterpret_cast<const sockaddr*>(&snapshot.sourceEndpoint),
                snapshot.sourceEndpointLength, snapshot.redirectContext,
                snapshot.redirectRecord, timeoutMilliseconds_, errorCode,
                registerSocket_, unregisterSocket_, callbackContext_);
            if (opened != WfpSocks5UdpFlowRelayResult::Pending) {
                relay->Close();
                flows_.Remove(flowId);
                return WfpUdpFlowRelayRegistryResult::RelayOpenFailed;
            }
            try {
                found = relays_.emplace(flowId, std::move(relay)).first;
                const auto queue = pendingDatagrams_.try_emplace(flowId);
                if (!queue.second) {
                    DiscardPendingDatagrams(flowId);
                    relays_.erase(flowId);
                    flows_.Remove(flowId);
                    return WfpUdpFlowRelayRegistryResult::RelayOpenFailed;
                }
                if (!QueuePendingDatagram(flowId, payload, message.payloadLength)) {
                    // The flow has no safe way to preserve its first datagram.
                    // Report bounded-queue rejection distinctly and release
                    // the just-created relay instead of disguising it as I/O failure.
                    DiscardPendingDatagrams(flowId);
                    relays_.erase(flowId);
                    flows_.Remove(flowId);
                    return WfpUdpFlowRelayRegistryResult::PendingQueueFull;
                }
            } catch (...) {
                // Roll back both socket resources and any partially created
                // queue entry; accounting must remain balanced on allocation failure.
                DiscardPendingDatagrams(flowId);
                relays_.erase(flowId);
                flows_.Remove(flowId);
                return WfpUdpFlowRelayRegistryResult::RelayOpenFailed;
            }
            if (outputFlowId) *outputFlowId = flowId;
            return WfpUdpFlowRelayRegistryResult::Pending;
        }
    }

    if (found == relays_.end())
        return WfpUdpFlowRelayRegistryResult::FlowNotFound;
    // Once a datagram is queued, later packets must join the same FIFO even
    // if the socket becomes writable between ingress events.
    if (outboundDatagrams_.find(flowId) != outboundDatagrams_.end()) {
        if (!QueueOutboundDatagram(flowId, payload, message.payloadLength)) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::PendingQueueFull;
        }
        if (outputFlowId) *outputFlowId = flowId;
        return WfpUdpFlowRelayRegistryResult::Pending;
    }

    const auto sent = found->second->SendClientPayload(
        payload, message.payloadLength, ioErrorCode);
    if (sent == WfpSocks5UdpFlowRelayResult::ControlClosed) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::ControlClosed;
    }
    if (sent == WfpSocks5UdpFlowRelayResult::SendWouldBlock) {
        try {
            outboundDatagrams_.try_emplace(flowId);
        } catch (...) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::SendFailed;
        }
        if (!QueueOutboundDatagram(flowId, payload, message.payloadLength)) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::PendingQueueFull;
        }
        if (outputFlowId) *outputFlowId = flowId;
        return WfpUdpFlowRelayRegistryResult::Pending;
    }
    if (sent != WfpSocks5UdpFlowRelayResult::Ready) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::SendFailed;
    }
    if (outputFlowId) *outputFlowId = flowId;
    return WfpUdpFlowRelayRegistryResult::Ready;
}


WfpUdpFlowRelayRegistryResult WfpUdpFlowRelayRegistry::AdvancePendingFlow(
    std::uint64_t flowId, bool readable, bool writable, int* errorCode) noexcept {
    if (errorCode) *errorCode = 0;
    int localErrorCode = 0;
    int* ioErrorCode = errorCode != nullptr ? errorCode : &localErrorCode;
    const auto relay = relays_.find(flowId);
    const auto pending = pendingDatagrams_.find(flowId);
    if (relay == relays_.end() || pending == pendingDatagrams_.end())
        return WfpUdpFlowRelayRegistryResult::FlowNotFound;

    const auto advanced = relay->second->AdvanceOpen(readable, writable, errorCode);
    if (advanced == WfpSocks5UdpFlowRelayResult::Pending)
        return WfpUdpFlowRelayRegistryResult::Pending;
    if (advanced != WfpSocks5UdpFlowRelayResult::Ready) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::RelayOpenFailed;
    }

    // Preserve datagram order. If the local UDP socket cannot accept a queued
    // datagram, fail this flow closed rather than silently dropping/reordering it.
    while (!pending->second.empty()) {
        const auto& datagram = pending->second.front();
        // Detect corrupted global accounting before the datagram can be sent.
        if (datagram.size() > pendingDatagramBytes_) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::SendFailed;
        }
        const auto sent = relay->second->SendClientPayload(
            datagram.empty() ? nullptr : datagram.data(), datagram.size(), ioErrorCode);
        if (sent == WfpSocks5UdpFlowRelayResult::SendWouldBlock) {
            // Handshake buffering transitions atomically to the writable-event
            // queue. Preserve the unsent suffix in FIFO order and keep the
            // combined global byte budget unchanged.
            try {
                auto outbound = outboundDatagrams_.try_emplace(flowId);
                if (!outbound.second) {
                    CloseFlow(flowId);
                    return WfpUdpFlowRelayRegistryResult::SendFailed;
                }
                while (!pending->second.empty()) {
                    auto& next = pending->second.front();
                    const auto size = next.size();
                    // Validate accounting before moving from the source queue.
                    // Otherwise a mismatch could leave a moved-from datagram in
                    // pendingDatagrams_ and make CloseFlow unable to reconcile
                    // the global pending-byte counter.
                    if (size > pendingDatagramBytes_ ||
                        outboundDatagramBytes_ > kMaximumPendingDatagramBytes ||
                        size > kMaximumPendingDatagramBytes - outboundDatagramBytes_) {
                        CloseFlow(flowId);
                        return WfpUdpFlowRelayRegistryResult::SendFailed;
                    }
                    outbound.first->second.push_back(std::move(next));
                    pendingDatagramBytes_ -= size;
                    outboundDatagramBytes_ += size;
                    pending->second.pop_front();
                }
            } catch (...) {
                CloseFlow(flowId);
                return WfpUdpFlowRelayRegistryResult::SendFailed;
            }
            pendingDatagrams_.erase(pending);
            return WfpUdpFlowRelayRegistryResult::Pending;
        }
        if (sent != WfpSocks5UdpFlowRelayResult::Ready) {
            CloseFlow(flowId);
            return sent == WfpSocks5UdpFlowRelayResult::ControlClosed
                ? WfpUdpFlowRelayRegistryResult::ControlClosed
                : WfpUdpFlowRelayRegistryResult::SendFailed;
        }
        if (datagram.size() > pendingDatagramBytes_) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::SendFailed;
        }
        pendingDatagramBytes_ -= datagram.size();
        pending->second.pop_front();
    }
    pendingDatagrams_.erase(pending);
    return WfpUdpFlowRelayRegistryResult::Ready;
}

WfpUdpFlowRelayRegistryResult WfpUdpFlowRelayRegistry::AdvanceQueuedClientDatagrams(
    std::uint64_t flowId, int* errorCode) noexcept {
    if (errorCode) *errorCode = 0;
    int localError = 0;
    int* sendError = errorCode != nullptr ? errorCode : &localError;
    const auto relay = relays_.find(flowId);
    const auto queued = outboundDatagrams_.find(flowId);
    if (relay == relays_.end() || queued == outboundDatagrams_.end())
        return WfpUdpFlowRelayRegistryResult::FlowNotFound;

    while (!queued->second.empty()) {
        const auto& datagram = queued->second.front();
        // Do not emit a datagram if its queue accounting is already invalid.
        if (datagram.size() > outboundDatagramBytes_) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::SendFailed;
        }
        const auto sent = relay->second->SendClientPayload(
            datagram.empty() ? nullptr : datagram.data(), datagram.size(), sendError);
        if (sent == WfpSocks5UdpFlowRelayResult::ControlClosed) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::ControlClosed;
        }
        if (sent == WfpSocks5UdpFlowRelayResult::SendWouldBlock) {
            return WfpUdpFlowRelayRegistryResult::Pending;
        }
        if (sent != WfpSocks5UdpFlowRelayResult::Ready) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::SendFailed;
        }
        const auto size = datagram.size();
        if (size > outboundDatagramBytes_) {
            CloseFlow(flowId);
            return WfpUdpFlowRelayRegistryResult::SendFailed;
        }
        outboundDatagramBytes_ -= size;
        queued->second.pop_front();
    }
    outboundDatagrams_.erase(queued);
    return WfpUdpFlowRelayRegistryResult::Ready;
}

WfpUdpFlowRelayRegistryResult WfpUdpFlowRelayRegistry::HandleUpstreamResponse(
    std::uint64_t flowId, SOCKET ingress, LPFN_WSASENDMSG sendMessage,
    std::uint8_t* buffer, std::size_t capacity, TimePoint now,
    int* errorCode) noexcept {
    const auto found = relays_.find(flowId);
    if (found == relays_.end()) return WfpUdpFlowRelayRegistryResult::FlowNotFound;
    if (pendingDatagrams_.find(flowId) != pendingDatagrams_.end())
        return WfpUdpFlowRelayRegistryResult::Pending;

    // Upstream traffic is not client activity. Check the lease without
    // refreshing it, otherwise unsolicited responses can keep idle flows alive.
    if (!flows_.IsActive(flowId, now)) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::FlowNotFound;
    }

    Socks5UdpDatagramView response{};
    std::size_t received = 0;
    const auto result = found->second->ReceiveUpstreamResponse(
        buffer, capacity, response, received, errorCode);
    if (result == WfpSocks5UdpFlowRelayResult::ReceivePending ||
        result == WfpSocks5UdpFlowRelayResult::ReceiveDropped)
        return WfpUdpFlowRelayRegistryResult::ReceivePending;
    if (result == WfpSocks5UdpFlowRelayResult::UnexpectedDestination)
        return WfpUdpFlowRelayRegistryResult::UnexpectedDestination;
    if (result == WfpSocks5UdpFlowRelayResult::ControlClosed) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::ControlClosed;
    }
    if (result != WfpSocks5UdpFlowRelayResult::Ready) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::ReceiveFailed;
    }

    const auto forwarded = found->second->ForwardUpstreamResponse(
        ingress, sendMessage, response);
    if (forwarded == WfpSocks5UdpFlowRelayResult::ControlClosed) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::ControlClosed;
    }
    if (forwarded != WfpSocks5UdpFlowRelayResult::Ready) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::ForwardFailed;
    }

    // Only a validated response that was actually forwarded may extend the
    // flow lease. The broker owns this registry on one I/O thread.
    std::uint64_t touchedFlowId = 0;
    const auto touchResult = flows_.Touch(
        found->second->OriginalClient(),
        found->second->OriginalClientLength(), now, touchedFlowId);
    if (touchResult != WfpUdpFlowTouchResult::Found ||
        touchedFlowId != flowId) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::FlowNotFound;
    }
    return WfpUdpFlowRelayRegistryResult::Ready;
}

std::size_t WfpUdpFlowRelayRegistry::SweepExpired(TimePoint now) noexcept {
    // Close each expired relay before removing its flow identity. This avoids
    // the allocating ID snapshot, whose failure previously looked identical
    // to "nothing expired" and could indefinitely defer cleanup under pressure.
    std::size_t closed = 0;
    std::uint64_t expiredFlowId = 0;
    std::size_t scanIndex = 0;
    // CloseFlowResources releases sockets and queues; RemoveAt then removes
    // the exact flow entry. Keeping scanIndex at that position visits the last
    // entry swapped into it, so the sweep remains O(n) without skipping flows.
    while (flows_.FindExpiredFrom(now, scanIndex, expiredFlowId)) {
        CloseFlowResources(expiredFlowId);
        if (!flows_.RemoveAt(scanIndex, expiredFlowId)) {
            // Prefer the identity-based fallback if the scan index became
            // stale. Resources are already closed, so retaining the Flow
            // entry would leave an unusable identity occupying flow quotas.
            if (!flows_.Remove(expiredFlowId)) break;
        }
        ++closed;
    }
    return closed;
}

std::size_t WfpUdpFlowRelayRegistry::SweepClosedControls() noexcept {
    std::size_t closed = 0;
    for (auto it = relays_.begin(); it != relays_.end();) {
        // During SOCKS5 negotiation, readable bytes are protocol replies, not
        // proof that the reserved control channel has been closed.
        if (pendingDatagrams_.find(it->first) != pendingDatagrams_.end() ||
            it->second->IsControlAlive()) {
            ++it;
            continue;
        }
        const auto flowId = it->first;
        ++it; // Erasing the current element does not invalidate other iterators.
        CloseFlow(flowId);
        ++closed;
    }
    return closed;
}


std::size_t WfpUdpFlowRelayRegistry::PendingDatagramCount(
    std::uint64_t flowId) const noexcept {
    std::size_t count = 0;
    const auto pending = pendingDatagrams_.find(flowId);
    if (pending != pendingDatagrams_.end()) count += pending->second.size();
    const auto outbound = outboundDatagrams_.find(flowId);
    if (outbound != outboundDatagrams_.end()) count += outbound->second.size();
    return count;
}

bool WfpUdpFlowRelayRegistry::QueuePendingDatagram(
    std::uint64_t flowId, const std::uint8_t* payload,
    std::size_t payloadLength) noexcept {
    auto found = pendingDatagrams_.find(flowId);
    const std::size_t usedBytes = pendingDatagramBytes_ + outboundDatagramBytes_;
    if (found == pendingDatagrams_.end() ||
        PendingDatagramCount(flowId) >= kMaximumPendingDatagramsPerFlow ||
        payloadLength > 65507 ||
        pendingDatagramBytes_ > kMaximumPendingDatagramBytes ||
        outboundDatagramBytes_ > kMaximumPendingDatagramBytes - pendingDatagramBytes_ ||
        payloadLength > kMaximumPendingDatagramBytes - usedBytes ||
        (payloadLength != 0 && payload == nullptr)) return false;
    try {
        std::vector<std::uint8_t> datagram;
        if (payloadLength != 0) datagram.assign(payload, payload + payloadLength);
        found->second.push_back(std::move(datagram));
        pendingDatagramBytes_ += payloadLength;
        return true;
    } catch (...) {
        return false;
    }
}

void WfpUdpFlowRelayRegistry::RecalculateQueueByteCounts() noexcept {
    // Rebuild accounting from the surviving queues after cleanup. This avoids
    // saturating subtraction hiding an earlier counter mismatch and poisoning
    // the global queue budget for subsequent flows.
    const auto addSaturated = [](std::size_t& total, std::size_t amount) noexcept {
        const auto maximum = (std::numeric_limits<std::size_t>::max)();
        total = amount > maximum - total ? maximum : total + amount;
    };

    pendingDatagramBytes_ = 0;
    for (const auto& item : pendingDatagrams_) {
        for (const auto& datagram : item.second)
            addSaturated(pendingDatagramBytes_, datagram.size());
    }

    outboundDatagramBytes_ = 0;
    for (const auto& item : outboundDatagrams_) {
        for (const auto& datagram : item.second)
            addSaturated(outboundDatagramBytes_, datagram.size());
    }
}

void WfpUdpFlowRelayRegistry::DiscardPendingDatagrams(
    std::uint64_t flowId) noexcept {
    const auto found = pendingDatagrams_.find(flowId);
    if (found == pendingDatagrams_.end()) return;
    pendingDatagrams_.erase(found);
    RecalculateQueueByteCounts();
}

bool WfpUdpFlowRelayRegistry::QueueOutboundDatagram(
    std::uint64_t flowId, const std::uint8_t* payload,
    std::size_t payloadLength) noexcept {
    auto found = outboundDatagrams_.find(flowId);
    const std::size_t usedBytes = pendingDatagramBytes_ + outboundDatagramBytes_;
    if (found == outboundDatagrams_.end() ||
        PendingDatagramCount(flowId) >= kMaximumPendingDatagramsPerFlow ||
        payloadLength > 65507 ||
        pendingDatagramBytes_ > kMaximumPendingDatagramBytes ||
        outboundDatagramBytes_ > kMaximumPendingDatagramBytes - pendingDatagramBytes_ ||
        payloadLength > kMaximumPendingDatagramBytes - usedBytes ||
        (payloadLength != 0 && payload == nullptr)) return false;
    try {
        std::vector<std::uint8_t> datagram;
        if (payloadLength != 0) datagram.assign(payload, payload + payloadLength);
        found->second.push_back(std::move(datagram));
        outboundDatagramBytes_ += payloadLength;
        return true;
    } catch (...) {
        return false;
    }
}

void WfpUdpFlowRelayRegistry::DiscardOutboundDatagrams(
    std::uint64_t flowId) noexcept {
    const auto found = outboundDatagrams_.find(flowId);
    if (found == outboundDatagrams_.end()) return;
    outboundDatagrams_.erase(found);
    RecalculateQueueByteCounts();
}

void WfpUdpFlowRelayRegistry::CloseFlowResources(std::uint64_t flowId) noexcept {
    DiscardPendingDatagrams(flowId);
    DiscardOutboundDatagrams(flowId);
    const auto found = relays_.find(flowId);
    if (found != relays_.end()) {
        found->second->Close();
        relays_.erase(found);
    }
}

void WfpUdpFlowRelayRegistry::CloseFlow(std::uint64_t flowId) noexcept {
    CloseFlowResources(flowId);
    flows_.Remove(flowId);
}

void WfpUdpFlowRelayRegistry::CloseAll() noexcept {
    // Close socket owners first, then discard any orphaned queue state. This
    // path must not allocate: it is also used during shutdown and recovery
    // after an allocation failure in the I/O loop.
    while (!relays_.empty()) {
        const auto id = relays_.begin()->first;
        CloseFlow(id);
    }
    pendingDatagrams_.clear();
    outboundDatagrams_.clear();
    pendingDatagramBytes_ = 0;
    outboundDatagramBytes_ = 0;
    flows_.Clear();
}

std::size_t WfpUdpFlowRelayRegistry::ActiveCount() const noexcept {
    return relays_.size();
}

bool WfpUdpFlowRelayRegistry::GetRelaySockets(
    std::vector<WfpUdpRelaySocket>& output) const noexcept {
    output.clear();
    try {
        output.reserve(relays_.size());
        for (const auto& item : relays_) {
            output.push_back({item.first, item.second->UdpSocket(),
                item.second->ControlSocket(),
                item.second->IsOpening(),
                item.second->WantsRead(), item.second->WantsWrite(),
                item.second->OriginalClient() != nullptr
                    ? item.second->OriginalClient()->sa_family : AF_UNSPEC,
                outboundDatagrams_.find(item.first) != outboundDatagrams_.end()});
        }
    } catch (...) {
        output.clear();
        return false;
    }
    return true;
}

} // namespace furious::wfp::broker
