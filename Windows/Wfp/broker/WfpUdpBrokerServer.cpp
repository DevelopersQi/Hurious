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

void SetNonblocking(SOCKET socket) noexcept {
    u_long enabled = 1;
    ioctlsocket(socket, FIONBIO, &enabled);
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

    SetNonblocking(ingress.socket);
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

    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
    winsockStarted_ = true;

    bool anyIngress = false;
    if (enableIpv4) anyIngress = CreateIngress(AF_INET, ipv4_) || anyIngress;
    if (enableIpv6) anyIngress = CreateIngress(AF_INET6, ipv6_) || anyIngress;
    if (!anyIngress || !registry_.Configure(socksAddress, socksAddressLength)) {
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
        registry_.CloseAll();
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
    registry_.CloseAll();
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
        registry_.CloseAll();
        return;
    }

    auto nextSweep = std::chrono::steady_clock::now();
    while (!stopping_.load()) {
        std::vector<WSAPOLLFD> descriptors;
        std::vector<PollTarget> targets;
        std::vector<WfpUdpRelaySocket> relays;
        try {
            descriptors.reserve(2 + 256);
            targets.reserve(2 + 256);
            if (ipv4_.socket != INVALID_SOCKET) {
                descriptors.push_back({ipv4_.socket, POLLRDNORM, 0});
                targets.push_back({PollKind::Ingress4, ipv4_.socket, 0});
            }
            if (ipv6_.socket != INVALID_SOCKET) {
                descriptors.push_back({ipv6_.socket, POLLRDNORM, 0});
                targets.push_back({PollKind::Ingress6, ipv6_.socket, 0});
            }
            if (!registry_.GetRelaySockets(relays)) {
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
                    descriptors.push_back({relay.socket, POLLRDNORM, 0});
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
                Ingress& ingress = target.kind == PollKind::Ingress4 ? ipv4_ : ipv6_;
                WfpUdpReceivedMessage message{};
                int error = 0;
                const auto received = ReceiveWfpUdpMessage(ingress.socket,
                    ingress.receiveMessage, payload.data(), payload.size(),
                    control.data(), control.size(), message, &error);
                if (received == WfpUdpReceiveResult::Received) {
                    registry_.ProcessClientDatagram(message, payload.data(),
                        WfpUdpFlowRelayRegistry::Clock::now(), nullptr, &error);
                }
            } else if (target.kind == PollKind::PendingControl) {
                const bool readable = (events & (POLLRDNORM | POLLERR | POLLHUP)) != 0;
                const bool writable = (events & (POLLWRNORM | POLLERR | POLLHUP)) != 0;
                registry_.AdvancePendingFlow(target.flowId, readable, writable);
            } else if (target.kind == PollKind::RelayUdp) {
                const auto relay = std::find_if(relays.begin(), relays.end(),
                    [&target](const WfpUdpRelaySocket& value) {
                        return value.flowId == target.flowId;
                    });
                if (relay != relays.end()) {
                    Ingress& ingress = relay->clientAddressFamily == AF_INET6
                        ? ipv6_ : ipv4_;
                    if (ingress.socket != INVALID_SOCKET) {
                        registry_.HandleUpstreamResponse(target.flowId,
                            ingress.socket, ingress.sendMessage, response.data(),
                            response.size(), WfpUdpFlowRelayRegistry::Clock::now());
                    }
                }
            } else if (target.kind == PollKind::ReadyControl) {
                registry_.SweepClosedControls();
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= nextSweep) {
            registry_.SweepExpired(now);
            registry_.SweepClosedControls();
            nextSweep = now + std::chrono::seconds(1);
        }
    }
    registry_.CloseAll();
}

} // namespace furious::wfp::broker
