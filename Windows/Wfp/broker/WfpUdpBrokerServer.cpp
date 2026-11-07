#include "WfpUdpBrokerServer.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ws2tcpip.h>

namespace furious::wfp::broker {
namespace {

enum class PollKind { Ingress4, Ingress6, RelayUdp, PendingControl, ReadyControl };

struct PollTarget final {
    PollKind kind;
    SOCKET socket;
    std::uint64_t flowId = 0;
};

bool SetNonblocking(SOCKET socket) noexcept {
    u_long enabled = 1;
    return ioctlsocket(socket, FIONBIO, &enabled) == 0;
}

} // namespace

UdpBrokerServer::~UdpBrokerServer() {
    Stop();
}

bool UdpBrokerServer::CreateIngress(int family, Ingress& ingress) noexcept {
    ingress = Ingress{};
    ingress.socket = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (ingress.socket == INVALID_SOCKET) return false;

    BOOL exclusive = TRUE;
    if (setsockopt(ingress.socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == SOCKET_ERROR) {
        CloseIngress(ingress);
        return false;
    }

    if (family == AF_INET) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(ingress.socket, reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) == SOCKET_ERROR) {
            CloseIngress(ingress);
            return false;
        }
        int length = sizeof(address);
        if (getsockname(ingress.socket, reinterpret_cast<sockaddr*>(&address),
                &length) == SOCKET_ERROR) {
            CloseIngress(ingress);
            return false;
        }
        ingress.port = ntohs(address.sin_port);
    } else if (family == AF_INET6) {
        DWORD onlyV6 = 1;
        if (setsockopt(ingress.socket, IPPROTO_IPV6, IPV6_V6ONLY,
                reinterpret_cast<const char*>(&onlyV6), sizeof(onlyV6)) == SOCKET_ERROR) {
            CloseIngress(ingress);
            return false;
        }
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_loopback;
        if (bind(ingress.socket, reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) == SOCKET_ERROR) {
            CloseIngress(ingress);
            return false;
        }
        int length = sizeof(address);
        if (getsockname(ingress.socket, reinterpret_cast<sockaddr*>(&address),
                &length) == SOCKET_ERROR) {
            CloseIngress(ingress);
            return false;
        }
        ingress.port = ntohs(address.sin6_port);
    } else {
        CloseIngress(ingress);
        return false;
    }

    if (!SetNonblocking(ingress.socket)) {
        CloseIngress(ingress);
        return false;
    }
    if (ResolveWsaRecvMsg(ingress.socket, &ingress.receiveMessage) != 0 ||
        ResolveWsaSendMsg(ingress.socket, &ingress.sendMessage) != 0 ||
        ingress.receiveMessage == nullptr || ingress.sendMessage == nullptr) {
        CloseIngress(ingress);
        return false;
    }
    return true;
}

void UdpBrokerServer::CloseIngress(Ingress& ingress) noexcept {
    if (ingress.socket != INVALID_SOCKET) closesocket(ingress.socket);
    ingress = Ingress{};
}

bool UdpBrokerServer::Start(const sockaddr* socksAddress, int socksAddressLength,
    bool enableIpv4, bool enableIpv6, std::size_t maximumFlows) noexcept {
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (!stopping_.load() || socksAddress == nullptr ||
        (!enableIpv4 && !enableIpv6) || maximumFlows == 0) return false;

    // The I/O loop can stop itself after a fatal poll/allocation/registry
    // failure. Reap that thread and release its sockets before a caller tries
    // to restart the broker; otherwise CreateIngress could overwrite a live
    // SOCKET value and leak the old loopback binding.
    if (ioThread_.joinable()) ioThread_.join();
    registry_.reset();
    CloseIngress(ipv4_);
    CloseIngress(ipv6_);
    ports_ = UdpBrokerListenerPorts{};
    if (winsockStarted_) {
        WSACleanup();
        winsockStarted_ = false;
    }

    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
    winsockStarted_ = true;

    try {
        // Respect the caller's global flow limit. Keep the per-process cap
        // bounded and never larger than the global cap.
        registry_ = std::make_unique<WfpUdpFlowRelayRegistry>(
            maximumFlows, (std::min)(maximumFlows, static_cast<std::size_t>(16)));
    } catch (...) {
        WSACleanup();
        winsockStarted_ = false;
        return false;
    }

    // Listener-family selection is part of the broker contract. Do not
    // silently downgrade a dual-stack request to one family: the service may
    // otherwise publish endpoint flags that cannot be honored by this broker.
    const bool ipv4Ready = !enableIpv4 || CreateIngress(AF_INET, ipv4_);
    const bool ipv6Ready = !enableIpv6 || CreateIngress(AF_INET6, ipv6_);
    if (!ipv4Ready || !ipv6Ready ||
        (ipv4_.socket == INVALID_SOCKET && ipv6_.socket == INVALID_SOCKET) ||
        !registry_->Configure(socksAddress, socksAddressLength)) {
        CloseIngress(ipv4_);
        CloseIngress(ipv6_);
        WSACleanup();
        winsockStarted_ = false;
        return false;
    }

    ports_.ipv4 = ipv4_.port;
    ports_.ipv6 = ipv6_.port;
    stopping_.store(false);
    try {
        ioThread_ = std::thread(&UdpBrokerServer::Run, this);
    } catch (...) {
        stopping_.store(true);
        registry_->CloseAll();
        CloseIngress(ipv4_);
        CloseIngress(ipv6_);
        ports_ = UdpBrokerListenerPorts{};
        WSACleanup();
        winsockStarted_ = false;
        return false;
    }
    return true;
}

void UdpBrokerServer::Stop() noexcept {
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    if (stopping_.exchange(true) && !winsockStarted_) return;
    if (ioThread_.joinable()) ioThread_.join();
    registry_->CloseAll();
    CloseIngress(ipv4_);
    CloseIngress(ipv6_);
    ports_ = UdpBrokerListenerPorts{};
    if (winsockStarted_) {
        WSACleanup();
        winsockStarted_ = false;
    }
}

bool UdpBrokerServer::IsRunning() const noexcept {
    return !stopping_.load();
}

UdpBrokerListenerPorts UdpBrokerServer::ListenerPorts() const noexcept {
    std::lock_guard<std::mutex> lock(lifecycleMutex_);
    return ports_;
}

void UdpBrokerServer::Run() noexcept {
    std::vector<std::uint8_t> payload;
    std::vector<char> control;
    std::vector<std::uint8_t> response;
    try {
        payload.resize(65507);
        response.resize(65507);
        control.resize(WSA_CMSG_SPACE(static_cast<ULONG>(kMaximumWfpUdpRedirectRecordSize)) +
            WSA_CMSG_SPACE(static_cast<ULONG>(sizeof(FURIOUS_WFP_REDIRECT_CONTEXT))) + 512);
    } catch (...) {
        stopping_.store(true);
        registry_->CloseAll();
        return;
    }

    // Reuse poll snapshots across iterations. The relay count is bounded by
    // the configured flow limit, and vector capacity is retained after clear(),
    // avoiding repeated heap churn on every 100 ms poll cycle.
    std::vector<WSAPOLLFD> descriptors;
    std::vector<PollTarget> targets;
    std::vector<WfpUdpRelaySocket> relays;
    std::vector<WfpUdpRelaySocket> pendingTimeouts;
    try {
        descriptors.reserve(2 + 256);
        targets.reserve(2 + 256);
        relays.reserve(256);
        pendingTimeouts.reserve(256);
    } catch (...) {
        stopping_.store(true);
        registry_->CloseAll();
        return;
    }

    auto nextSweep = std::chrono::steady_clock::now();
    while (!stopping_.load()) {
        descriptors.clear();
        targets.clear();
        try {
            if (ipv4_.socket != INVALID_SOCKET) {
                descriptors.push_back({ipv4_.socket, POLLRDNORM, 0});
                targets.push_back({PollKind::Ingress4, ipv4_.socket, 0});
            }
            if (ipv6_.socket != INVALID_SOCKET) {
                descriptors.push_back({ipv6_.socket, POLLRDNORM, 0});
                targets.push_back({PollKind::Ingress6, ipv6_.socket, 0});
            }
            if (!registry_->GetRelaySockets(relays)) {
                stopping_.store(true);
                break;
            }
            for (const auto& relay : relays) {
                if (relay.handshaking) {
                    SHORT events = 0;
                    if (relay.wantsRead) events |= POLLRDNORM;
                    if (relay.wantsWrite) events |= POLLWRNORM;
                    descriptors.push_back({relay.controlSocket, events, 0});
                    targets.push_back({PollKind::PendingControl,
                        relay.controlSocket, relay.flowId});
                } else {
                    const SHORT udpEvents = static_cast<SHORT>(
                        POLLRDNORM | (relay.wantsUdpWrite ? POLLWRNORM : 0));
                    descriptors.push_back({relay.socket, udpEvents, 0});
                    targets.push_back({PollKind::RelayUdp, relay.socket, relay.flowId});
                    descriptors.push_back({relay.controlSocket, POLLRDNORM, 0});
                    targets.push_back({PollKind::ReadyControl,
                        relay.controlSocket, relay.flowId});
                }
            }
        } catch (...) {
            stopping_.store(true);
            break;
        }

        const int ready = WSAPoll(descriptors.data(),
            static_cast<ULONG>(descriptors.size()), 100);
        if (ready == SOCKET_ERROR) {
            if (stopping_.load()) break;
            const int error = WSAGetLastError();
            if (error == WSAEINTR) continue;
            stopping_.store(true);
            break;
        }

        for (std::size_t index = 0; index < descriptors.size() && !stopping_.load(); ++index) {
            const SHORT events = descriptors[index].revents;
            if (events == 0) continue;
            const auto& target = targets[index];
            if (target.kind == PollKind::Ingress4 || target.kind == PollKind::Ingress6) {
                // An invalid or failed ingress socket means the published
                // endpoint can no longer receive redirected packets. Continuing
                // would leave WFP redirecting traffic into a dead broker.
                if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                    stopping_.store(true);
                    break;
                }
                Ingress& ingress = target.kind == PollKind::Ingress4 ? ipv4_ : ipv6_;
                WfpUdpReceivedMessage message{};
                int error = 0;
                const auto received = ReceiveWfpUdpMessage(ingress.socket,
                    ingress.receiveMessage, payload.data(), payload.size(),
                    control.data(), control.size(), message, &error);
                if (received == WfpUdpReceiveResult::Received) {
                    registry_->ProcessClientDatagram(message, payload.data(),
                        WfpUdpFlowRelayRegistry::Clock::now(), nullptr, &error);
                }
            } else if (target.kind == PollKind::PendingControl) {
                // POLLNVAL is not a readable/writable event, but it must drive
                // the pending state machine into its socket-error cleanup path
                // instead of leaving the flow allocated until its timeout.
                const bool invalid = (events & POLLNVAL) != 0;
                const bool readable = invalid ||
                    (events & (POLLRDNORM | POLLERR | POLLHUP)) != 0;
                const bool writable = invalid ||
                    (events & (POLLWRNORM | POLLERR | POLLHUP)) != 0;
                registry_->AdvancePendingFlow(target.flowId, readable, writable);
            } else if (target.kind == PollKind::RelayUdp) {
                // A failed relay datagram socket cannot recover its association.
                // Tear down the whole flow immediately instead of retaining a
                // dead UDP socket until the idle lease expires.
                if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                    registry_->CloseFlow(target.flowId);
                    continue;
                }
                const auto relay = std::find_if(relays.begin(), relays.end(),
                    [&target](const WfpUdpRelaySocket& value) {
                        return value.flowId == target.flowId;
                    });
                if (relay != relays.end()) {
                    // Writable notifications drain client->SOCKS packets in FIFO
                    // order. Keep the queue intact on WSAEWOULDBLOCK and resume
                    // only when WSAPoll reports the socket writable again.
                    if ((events & POLLWRNORM) != 0 && relay->wantsUdpWrite) {
                        registry_->AdvanceQueuedClientDatagrams(target.flowId);
                    }
                    if ((events & POLLRDNORM) != 0) {
                        Ingress& ingress = relay->clientAddressFamily == AF_INET6
                            ? ipv6_ : ipv4_;
                        if (ingress.socket != INVALID_SOCKET) {
                            registry_->HandleUpstreamResponse(target.flowId,
                                ingress.socket, ingress.sendMessage, response.data(),
                                response.size(), WfpUdpFlowRelayRegistry::Clock::now());
                        }
                    }
                }
            } else if (target.kind == PollKind::ReadyControl) {
                if ((events & (POLLERR | POLLHUP | POLLNVAL)) != 0)
                    registry_->CloseFlow(target.flowId);
                else
                    registry_->SweepClosedControls();
            }
        }

        // Advance pending handshakes even when the peer has sent no bytes;
        // this enforces each association's deadline without a per-flow timer.
        if (!registry_->GetRelaySockets(pendingTimeouts)) {
            // A failed snapshot means we cannot reliably enforce handshake
            // deadlines this iteration. Fail closed instead of silently
            // keeping pending control sockets alive without timeout service.
            stopping_.store(true);
            break;
        }
        for (const auto& relay : pendingTimeouts) {
            if (relay.handshaking)
                registry_->AdvancePendingFlow(relay.flowId, false, false);
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= nextSweep) {
            registry_->SweepExpired(now);
            registry_->SweepClosedControls();
            nextSweep = now + std::chrono::seconds(1);
        }
    }
    registry_->CloseAll();
}

} // namespace furious::wfp::broker
