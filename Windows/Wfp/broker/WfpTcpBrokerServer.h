#pragma once

#include "WfpTcpRedirect.h"

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

namespace furious::wfp::broker {

struct TcpBrokerListenerPorts final {
    std::uint16_t ipv4 = 0;
    std::uint16_t ipv6 = 0;
};

class TcpBrokerServer final {
public:
    TcpBrokerServer() = default;
    ~TcpBrokerServer();

    TcpBrokerServer(const TcpBrokerServer&) = delete;
    TcpBrokerServer& operator=(const TcpBrokerServer&) = delete;

    bool Start(
        const sockaddr* socksAddress,
        int socksAddressLength,
        bool enableIpv4 = true,
        bool enableIpv6 = true,
        size_t workerCount = 4,
        size_t maximumSessions = 128) noexcept;

    void Stop() noexcept;

    bool IsRunning() const noexcept;
    std::uint32_t ProcessId() const noexcept;
    TcpBrokerListenerPorts ListenerPorts() const noexcept;

private:
    bool CreateListener(int family, SOCKET& listener, std::uint16_t& port) noexcept;
    void AcceptLoop() noexcept;
    void WorkerLoop() noexcept;
    void ProcessClient(SOCKET client) noexcept;

    std::atomic<bool> stopping_{true};
    SOCKET ipv4Listener_ = INVALID_SOCKET;
    SOCKET ipv6Listener_ = INVALID_SOCKET;
    TcpBrokerListenerPorts ports_{};
    sockaddr_storage socksAddress_{};
    int socksAddressLength_ = 0;
    size_t maximumSessions_ = 128;
    std::atomic<size_t> sessionsInFlight_{0};
    bool winsockStarted_ = false;

    std::thread acceptThread_;
    std::vector<std::thread> workers_;

    mutable std::mutex queueMutex_;
    std::condition_variable queueChanged_;
    std::deque<SOCKET> pendingClients_;

    std::mutex activeMutex_;
    std::unordered_set<SOCKET> activeSockets_;
};

} // namespace furious::wfp::broker
