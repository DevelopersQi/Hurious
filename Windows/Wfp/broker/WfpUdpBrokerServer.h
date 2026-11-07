#pragma once

#include "WfpUdpFlowRelayRegistry.h"

#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

namespace furious::wfp::broker {

struct UdpBrokerListenerPorts final {
    std::uint16_t ipv4 = 0;
    std::uint16_t ipv6 = 0;
};

// A single-threaded UDP broker. One WSAPoll loop owns ingress sockets,
// pending SOCKS5 control handshakes, relay UDP sockets, and flow expiry.
class UdpBrokerServer final {
public:
    UdpBrokerServer() noexcept = default;
    ~UdpBrokerServer();

    UdpBrokerServer(const UdpBrokerServer&) = delete;
    UdpBrokerServer& operator=(const UdpBrokerServer&) = delete;

    bool Start(const sockaddr* socksAddress, int socksAddressLength,
        bool enableIpv4 = true, bool enableIpv6 = true,
        std::size_t maximumFlows = 128) noexcept;
    void Stop() noexcept;
    bool IsRunning() const noexcept;
    UdpBrokerListenerPorts ListenerPorts() const noexcept;

private:
    struct Ingress final {
        SOCKET socket = INVALID_SOCKET;
        std::uint16_t port = 0;
        LPFN_WSARECVMSG receiveMessage = nullptr;
        LPFN_WSASENDMSG sendMessage = nullptr;
    };

    bool CreateIngress(int family, Ingress& ingress) noexcept;
    void Run() noexcept;
    void CloseIngress(Ingress& ingress) noexcept;

    mutable std::mutex lifecycleMutex_;
    std::atomic<bool> stopping_{true};
    bool winsockStarted_ = false;
    Ingress ipv4_{};
    Ingress ipv6_{};
    UdpBrokerListenerPorts ports_{};
    WfpUdpFlowRelayRegistry registry_;
    std::thread ioThread_;
};

} // namespace furious::wfp::broker
