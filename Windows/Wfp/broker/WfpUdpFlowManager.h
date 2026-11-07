#pragma once

#include "WfpSocks5UdpRedirectRecord.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace furious::wfp::broker {

enum class WfpUdpFlowCreateResult {
    Created,
    ExistingFlow,
    ExpiredFlow,
    InvalidSource,
    InvalidContext,
    MissingRedirectRecord,
    RedirectRecordTooLarge,
    FlowLimitReached,
    PerProcessLimitReached,
    SourceEndpointConflict,
    AllocationFailure
};

enum class WfpUdpFlowTouchResult {
    Found,
    NotFound,
    Expired,
    InvalidSource
};

struct WfpUdpFlowSnapshot final {
    std::uint64_t id = 0;
    sockaddr_storage sourceEndpoint{};
    int sourceEndpointLength = 0;
    FURIOUS_WFP_REDIRECT_CONTEXT redirectContext{};
    std::vector<std::uint8_t> redirectRecord;
    std::chrono::steady_clock::time_point lastActivity{};
};

// Maps the first redirected UDP datagram's local source endpoint to its
// validated original destination and WFP redirect metadata. No socket I/O.
class WfpUdpFlowManager final {
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    explicit WfpUdpFlowManager(
        std::size_t maximumFlows = 512,
        std::size_t maximumFlowsPerProcess = 32,
        std::chrono::milliseconds idleTimeout = std::chrono::seconds(60)) noexcept;

    WfpUdpFlowManager(const WfpUdpFlowManager&) = delete;
    WfpUdpFlowManager& operator=(const WfpUdpFlowManager&) = delete;

    WfpUdpFlowCreateResult RegisterFirstDatagram(
        const sockaddr* sourceEndpoint,
        int sourceEndpointLength,
        const FURIOUS_WFP_REDIRECT_CONTEXT& redirectContext,
        const std::vector<std::uint8_t>& redirectRecord,
        TimePoint now,
        std::uint64_t& flowId) noexcept;

    WfpUdpFlowTouchResult Touch(
        const sockaddr* sourceEndpoint,
        int sourceEndpointLength,
        TimePoint now,
        std::uint64_t& flowId) noexcept;

    // Checks the idle lease without extending it. Used for untrusted upstream
    // traffic so a response cannot keep an otherwise idle flow alive.
    bool IsActive(std::uint64_t flowId, TimePoint now) const noexcept;

    bool GetSnapshot(std::uint64_t flowId, WfpUdpFlowSnapshot& output) const noexcept;
    bool Remove(std::uint64_t flowId) noexcept;
    // Clears all flow identities after the resource owner has closed relays.
    // Unlike SweepExpired(), this operation performs no allocation.
    void Clear() noexcept;
    std::size_t SweepExpired(TimePoint now) noexcept;
    // Reports expired IDs without erasing them. The owner must close relay resources,
    // then call Remove() for each ID.
    std::size_t SweepExpired(TimePoint now,
        std::vector<std::uint64_t>& expiredFlowIds) noexcept;
    std::size_t ActiveCount() const noexcept;
    std::size_t MaximumFlows() const noexcept;
    std::size_t MaximumFlowsPerProcess() const noexcept;

private:
    struct Entry final {
        std::uint64_t id = 0;
        sockaddr_storage sourceEndpoint{};
        int sourceEndpointLength = 0;
        FURIOUS_WFP_REDIRECT_CONTEXT redirectContext{};
        std::vector<std::uint8_t> redirectRecord;
        TimePoint lastActivity{};
    };

    static bool IsValidSourceEndpoint(
        const sockaddr* endpoint,
        int endpointLength) noexcept;
    static bool SameSourceEndpoint(
        const sockaddr_storage& a,
        int aLength,
        const sockaddr* b,
        int bLength) noexcept;
    static bool IsValidRedirectContext(
        const FURIOUS_WFP_REDIRECT_CONTEXT& context,
        int sourceAddressFamily) noexcept;
    static bool SameFlowIdentity(
        const Entry& entry,
        const FURIOUS_WFP_REDIRECT_CONTEXT& context,
        const std::vector<std::uint8_t>& redirectRecord) noexcept;
    bool IsExpired(const Entry& entry, TimePoint now) const noexcept;
    std::uint64_t AllocateId() noexcept;

    mutable std::mutex mutex_;
    const std::size_t maximumFlows_;
    const std::size_t maximumFlowsPerProcess_;
    const std::chrono::milliseconds idleTimeout_;
    std::uint64_t nextId_ = 1;
    std::vector<Entry> entries_;
};

} // namespace furious::wfp::broker
