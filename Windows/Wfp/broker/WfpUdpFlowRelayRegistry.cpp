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
    const auto touch = flows_.Touch(
        reinterpret_cast<const sockaddr*>(&message.sourceAddress),
        message.sourceAddressLength, now, flowId);
    if (touch == WfpUdpFlowTouchResult::InvalidSource)
        return WfpUdpFlowRelayRegistryResult::InvalidMessage;
    if (touch == WfpUdpFlowTouchResult::Expired) {
        CloseFlow(flowId);
        flowId = 0;
    }

    auto found = relays_.find(flowId);
    if (touch == WfpUdpFlowTouchResult::Found) {
        if (found == relays_.end()) {
            flows_.Remove(flowId);
            return WfpUdpFlowRelayRegistryResult::FlowNotFound;
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
            const auto opened = relay->Open(
                reinterpret_cast<const sockaddr*>(&socksAddress_), socksAddressLength_,
                reinterpret_cast<const sockaddr*>(&snapshot.sourceEndpoint),
                snapshot.sourceEndpointLength, snapshot.redirectContext,
                snapshot.redirectRecord, timeoutMilliseconds_, errorCode,
                registerSocket_, unregisterSocket_, callbackContext_);
            if (opened != WfpSocks5UdpFlowRelayResult::Ready) {
                relay->Close();
                flows_.Remove(flowId);
                return WfpUdpFlowRelayRegistryResult::RelayOpenFailed;
            }
            try {
                found = relays_.emplace(flowId, std::move(relay)).first;
            } catch (...) {
                // The unique_ptr closes the relay if map insertion fails.
                flows_.Remove(flowId);
                return WfpUdpFlowRelayRegistryResult::RelayOpenFailed;
            }
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

WfpUdpFlowRelayRegistryResult WfpUdpFlowRelayRegistry::HandleUpstreamResponse(
    std::uint64_t flowId, SOCKET ingress, LPFN_WSASENDMSG sendMessage,
    std::uint8_t* buffer, std::size_t capacity, TimePoint now,
    int* errorCode) noexcept {
    (void)now;
    const auto found = relays_.find(flowId);
    if (found == relays_.end()) return WfpUdpFlowRelayRegistryResult::FlowNotFound;
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
    if (result != WfpSocks5UdpFlowRelayResult::Ready)
        return WfpUdpFlowRelayRegistryResult::ReceiveFailed;

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
    flows_.Touch(found->second->OriginalClient(),
        found->second->OriginalClientLength(), now, flowId);
    return WfpUdpFlowRelayRegistryResult::Ready;
}

std::size_t WfpUdpFlowRelayRegistry::SweepExpired(TimePoint now) noexcept {
    std::vector<std::uint64_t> expired;
    const auto count = flows_.SweepExpired(now, expired);
    for (const auto id : expired) CloseFlow(id);
    return count;
}

void WfpUdpFlowRelayRegistry::CloseFlow(std::uint64_t flowId) noexcept {
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
            output.push_back({item.first, item.second->UdpSocket()});
        }
    } catch (...) {
        output.clear();
        return false;
    }
    return true;
}

} // namespace furious::wfp::broker
