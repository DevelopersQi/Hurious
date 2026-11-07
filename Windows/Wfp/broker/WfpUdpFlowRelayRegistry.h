#pragma once

#include "WfpSocks5UdpFlowRelay.h"
#include "WfpUdpFlowManager.h"

#include <memory>
#include <unordered_map>
#include <vector>

namespace furious::wfp::broker {

enum class WfpUdpFlowRelayRegistryResult {
    Ready,
    Pending,
    NotConfigured,
    InvalidMessage,
    MissingRedirectMetadata,
    InvalidRedirectMetadata,
    FlowLimitReached,
    RelayOpenFailed,
    SendFailed,
    FlowNotFound,
    ReceivePending,
    ReceiveFailed,
    UnexpectedDestination,
    ControlClosed,
    ForwardFailed
};

struct WfpUdpRelaySocket final {
    std::uint64_t flowId = 0;
    SOCKET socket = INVALID_SOCKET;
    SOCKET controlSocket = INVALID_SOCKET;
    bool handshaking = false;
};

// Single-I/O-thread owner for UDP flow state and per-flow SOCKS5 relay sockets.
// All public methods must be called by the same broker I/O thread.
class WfpUdpFlowRelayRegistry final {
public:
    using Clock = WfpUdpFlowManager::Clock;
    using TimePoint = WfpUdpFlowManager::TimePoint;

    explicit WfpUdpFlowRelayRegistry(
        std::size_t maximumFlows = 128,
        std::size_t maximumFlowsPerProcess = 16,
        std::chrono::milliseconds idleTimeout = std::chrono::seconds(60)) noexcept;
    ~WfpUdpFlowRelayRegistry();

    WfpUdpFlowRelayRegistry(const WfpUdpFlowRelayRegistry&) = delete;
    WfpUdpFlowRelayRegistry& operator=(const WfpUdpFlowRelayRegistry&) = delete;

    bool Configure(const sockaddr* socksAddress, int socksAddressLength,
        DWORD timeoutMilliseconds = 5000,
        ActiveSocketRegister registerSocket = nullptr,
        ActiveSocketUnregister unregisterSocket = nullptr,
        void* callbackContext = nullptr) noexcept;

    WfpUdpFlowRelayRegistryResult ProcessClientDatagram(
        const WfpUdpReceivedMessage& message,
        const std::uint8_t* payload, TimePoint now,
        std::uint64_t* flowId = nullptr, int* errorCode = nullptr) noexcept;

    WfpUdpFlowRelayRegistryResult AdvancePendingFlow(
        std::uint64_t flowId, bool readable, bool writable,
        int* errorCode = nullptr) noexcept;

    WfpUdpFlowRelayRegistryResult HandleUpstreamResponse(
        std::uint64_t flowId, SOCKET redirectedIngressSocket,
        LPFN_WSASENDMSG sendMessage, std::uint8_t* buffer,
        std::size_t capacity, TimePoint now,
        int* errorCode = nullptr) noexcept;

    std::size_t SweepExpired(TimePoint now) noexcept;
    std::size_t SweepClosedControls() noexcept;
    void CloseAll() noexcept;
    std::size_t ActiveCount() const noexcept;
    bool GetRelaySockets(std::vector<WfpUdpRelaySocket>& output) const noexcept;

private:
    void CloseFlow(std::uint64_t flowId) noexcept;

    WfpUdpFlowManager flows_;
    std::unordered_map<std::uint64_t, std::unique_ptr<WfpSocks5UdpFlowRelay>> relays_;
    std::unordered_map<std::uint64_t, std::vector<std::uint8_t>> pendingDatagrams_;
    sockaddr_storage socksAddress_{};
    int socksAddressLength_ = 0;
    DWORD timeoutMilliseconds_ = 5000;
    ActiveSocketRegister registerSocket_ = nullptr;
    ActiveSocketUnregister unregisterSocket_ = nullptr;
    void* callbackContext_ = nullptr;
};

} // namespace furious::wfp::broker
