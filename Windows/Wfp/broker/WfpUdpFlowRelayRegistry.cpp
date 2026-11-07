#include "WfpUdpFlowRelayRegistry.h"

#include <cstring>
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
            flows_.Remove(flowId);
            return WfpUdpFlowRelayRegistryResult::FlowNotFound;
        }
        if (pendingDatagrams_.find(flowId) != pendingDatagrams_.end()) {
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
            if (!flows_.GetSnapshot(flowId, snapshot))
                return WfpUdpFlowRelayRegistryResult::FlowNotFound;
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
                std::vector<std::uint8_t> firstDatagram;
                if (message.payloadLength != 0)
                    firstDatagram.assign(payload, payload + message.payloadLength);
                pendingDatagrams_.emplace(flowId, std::move(firstDatagram));
            } catch (...) {
                // Erasing the relay closes its UDP and TCP resources.
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
    const auto sent = found->second->SendClientPayload(
        payload, message.payloadLength, errorCode);
    if (sent == WfpSocks5UdpFlowRelayResult::ControlClosed) {
        CloseFlow(flowId);
        return WfpUdpFlowRelayRegistryResult::ControlClosed;
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

    const auto sent = relay->second->SendClientPayload(
        pending->second.empty() ? nullptr : pending->second.data(),
        pending->second.size(), errorCode);
    if (sent != WfpSocks5UdpFlowRelayResult::Ready) {
        CloseFlow(flowId);
        return sent == WfpSocks5UdpFlowRelayResult::ControlClosed
            ? WfpUdpFlowRelayRegistryResult::ControlClosed
            : WfpUdpFlowRelayRegistryResult::SendFailed;
    }
    pendingDatagrams_.erase(pending);
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
    if (result == WfpSocks5UdpFlowRelayResult::ReceivePending)
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
    std::vector<std::uint64_t> expired;
    const auto count = flows_.SweepExpired(now, expired);
    for (const auto id : expired) CloseFlow(id);
    return count;
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
        pendingDatagrams_.erase(flowId);
        it->second->Close();
        it = relays_.erase(it);
        flows_.Remove(flowId);
        ++closed;
    }
    return closed;
}

void WfpUdpFlowRelayRegistry::CloseFlow(std::uint64_t flowId) noexcept {
    pendingDatagrams_.erase(flowId);
    const auto found = relays_.find(flowId);
    if (found != relays_.end()) {
        found->second->Close();
        relays_.erase(found);
    }
    flows_.Remove(flowId);
}

void WfpUdpFlowRelayRegistry::CloseAll() noexcept {
    while (!relays_.empty()) {
        const auto id = relays_.begin()->first;
        CloseFlow(id);
    }
    std::vector<std::uint64_t> remaining;
    flows_.SweepExpired(TimePoint::max(), remaining);
    for (const auto id : remaining) flows_.Remove(id);
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
                pendingDatagrams_.find(item.first) != pendingDatagrams_.end(),
                item.second->WantsRead(), item.second->WantsWrite()});
        }
    } catch (...) {
        output.clear();
        return false;
    }
    return true;
}

} // namespace furious::wfp::broker
