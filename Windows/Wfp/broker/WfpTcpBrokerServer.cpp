#include "WfpTcpBrokerServer.h"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace furious::wfp::broker {
namespace {

bool IsLoopbackSocksAddress(const sockaddr* address) noexcept {
    if (address == nullptr) return false;
    if (address->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
        return (ntohl(ipv4->sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u;
    }
    if (address->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(address);
        return IN6_IS_ADDR_LOOPBACK(&ipv6->sin6_addr) != 0;
    }
    return false;
}

void CloseSocket(SOCKET& socket) noexcept {
    if (socket != INVALID_SOCKET) {
        closesocket(socket);
        socket = INVALID_SOCKET;
    }
}

} // namespace

TcpBrokerServer::~TcpBrokerServer() {
    Stop();
}

bool TcpBrokerServer::CreateListener(
    int family,
    SOCKET& listener,
    std::uint16_t& port) noexcept {
    listener = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET) {
        return false;
    }

    BOOL exclusive = TRUE;
    if (setsockopt(listener, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == SOCKET_ERROR) {
        CloseSocket(listener);
        return false;
    }

    if (family == AF_INET) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (bind(listener, reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) == SOCKET_ERROR) {
            CloseSocket(listener);
            return false;
        }

        int length = sizeof(address);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address),
                &length) == SOCKET_ERROR) {
            CloseSocket(listener);
            return false;
        }
        port = ntohs(address.sin_port);
    } else if (family == AF_INET6) {
        DWORD onlyV6 = 1;
        if (setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY,
                reinterpret_cast<const char*>(&onlyV6), sizeof(onlyV6)) == SOCKET_ERROR) {
            CloseSocket(listener);
            return false;
        }

        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_loopback;
        address.sin6_port = 0;
        if (bind(listener, reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) == SOCKET_ERROR) {
            CloseSocket(listener);
            return false;
        }

        int length = sizeof(address);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address),
                &length) == SOCKET_ERROR) {
            CloseSocket(listener);
            return false;
        }
        port = ntohs(address.sin6_port);
    } else {
        CloseSocket(listener);
        return false;
    }

    if (listen(listener, SOMAXCONN) == SOCKET_ERROR) {
        CloseSocket(listener);
        port = 0;
        return false;
    }
    u_long nonblocking = 1;
    if (ioctlsocket(listener, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        CloseSocket(listener);
        port = 0;
        return false;
    }
    return true;
}

bool TcpBrokerServer::Start(
    const sockaddr* socksAddress,
    int socksAddressLength,
    bool enableIpv4,
    bool enableIpv6,
    size_t workerCount,
    size_t maximumSessions) noexcept {
    std::lock_guard<std::recursive_mutex> lifecycleLock(lifecycleMutex_);
    if (!stopping_.load() || socksAddress == nullptr ||
        !IsLoopbackSocksAddress(socksAddress) ||
        (!enableIpv4 && !enableIpv6) ||
        workerCount == 0 || maximumSessions == 0) {
        return false;
    }

    const int expectedLength = socksAddress->sa_family == AF_INET
        ? sizeof(sockaddr_in)
        : socksAddress->sa_family == AF_INET6
            ? sizeof(sockaddr_in6) : 0;
    if (expectedLength == 0 || socksAddressLength < expectedLength) {
        return false;
    }
    const std::uint16_t socksPort = socksAddress->sa_family == AF_INET
        ? ntohs(reinterpret_cast<const sockaddr_in*>(socksAddress)->sin_port)
        : ntohs(reinterpret_cast<const sockaddr_in6*>(socksAddress)->sin6_port);
    if (socksPort == 0) {
        return false;
    }

    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        return false;
    }
    winsockStarted_ = true;

    std::memset(&socksAddress_, 0, sizeof(socksAddress_));
    std::memcpy(&socksAddress_, socksAddress,
        static_cast<size_t>(expectedLength));
    socksAddressLength_ = expectedLength;
    maximumSessions_ = maximumSessions;
    ports_ = TcpBrokerListenerPorts{};

    bool anyListener = false;
    if (enableIpv4) {
        anyListener = CreateListener(AF_INET, ipv4Listener_, ports_.ipv4) || anyListener;
    }
    if (enableIpv6) {
        anyListener = CreateListener(AF_INET6, ipv6Listener_, ports_.ipv6) || anyListener;
    }
    if (!anyListener) {
        Stop();
        return false;
    }

    stopping_.store(false);
    try {
        workers_.reserve(workerCount);
        for (size_t index = 0; index < workerCount; ++index) {
            workers_.emplace_back(&TcpBrokerServer::WorkerLoop, this);
        }
        acceptThread_ = std::thread(&TcpBrokerServer::AcceptLoop, this);
    } catch (...) {
        Stop();
        return false;
    }
    return true;
}

void TcpBrokerServer::AcceptLoop() noexcept {
    while (!stopping_.load()) {
        fd_set readable;
        FD_ZERO(&readable);
        if (ipv4Listener_ != INVALID_SOCKET) {
            FD_SET(ipv4Listener_, &readable);
        }
        if (ipv6Listener_ != INVALID_SOCKET) {
            FD_SET(ipv6Listener_, &readable);
        }
        timeval timeout{1, 0};
        const int ready = select(0, &readable, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR) {
            if (stopping_.load()) {
                break;
            }
            continue;
        }
        if (ready == 0) {
            continue;
        }

        const SOCKET listeners[] = {ipv4Listener_, ipv6Listener_};
        for (SOCKET listener : listeners) {
            if (listener == INVALID_SOCKET || !FD_ISSET(listener, &readable)) {
                continue;
            }

            // Do not let a continuous stream of inbound connections starve Stop().
            // The listener is nonblocking, so this loop must re-check the stop
            // signal between accepts instead of draining forever under load.
            while (!stopping_.load()) {
                SOCKET client = accept(listener, nullptr, nullptr);
                if (client == INVALID_SOCKET) {
                    const int error = WSAGetLastError();
                    if (error != WSAEWOULDBLOCK && error != WSAEINTR &&
                        !stopping_.load()) {
                        Sleep(10);
                    }
                    break;
                }

                bool queued = false;
                {
                    std::lock_guard<std::mutex> lock(queueMutex_);
                    if (!stopping_.load() &&
                        sessionsInFlight_.load() < maximumSessions_) {
                        try {
                            pendingClients_.push_back(client);
                            sessionsInFlight_.fetch_add(1);
                            queued = true;
                        } catch (...) {
                            queued = false;
                        }
                    }
                }
                if (queued) {
                    queueChanged_.notify_one();
                } else {
                    closesocket(client);
                }
            }
        }
    }
}

void TcpBrokerServer::WorkerLoop() noexcept {
    for (;;) {
        SOCKET client = INVALID_SOCKET;
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            queueChanged_.wait(lock, [this]() {
                return stopping_.load() || !pendingClients_.empty();
            });
            if (stopping_.load() && pendingClients_.empty()) {
                return;
            }
            client = pendingClients_.front();
            pendingClients_.pop_front();
        }

        ProcessClient(client);
        sessionsInFlight_.fetch_sub(1);
    }
}

void TcpBrokerServer::ProcessClient(SOCKET client) noexcept {
    {
        std::lock_guard<std::mutex> lock(activeMutex_);
        if (stopping_.load()) {
            closesocket(client);
            return;
        }
        try {
            activeSockets_.insert(client);
        } catch (...) {
            closesocket(client);
            return;
        }
    }

    RedirectedTcpConnection redirected;
    int error = QueryRedirectedTcpConnection(client, redirected);
    SOCKET upstream = INVALID_SOCKET;

    if (error == 0) {
        upstream = OpenSocks5Tunnel(
            reinterpret_cast<const sockaddr*>(&socksAddress_),
            socksAddressLength_,
            redirected,
            &error);
    }

    if (upstream != INVALID_SOCKET) {
        bool keep = false;
        {
            std::lock_guard<std::mutex> lock(activeMutex_);
            if (!stopping_.load()) {
                try {
                    activeSockets_.insert(upstream);
                    keep = true;
                } catch (...) {
                    keep = false;
                }
            }
        }
        if (keep) {
            RelayBidirectional(client, upstream);
        } else {
            shutdown(upstream, SD_BOTH);
        }
    }

    {
        std::lock_guard<std::mutex> lock(activeMutex_);
        activeSockets_.erase(client);
        if (upstream != INVALID_SOCKET) {
            activeSockets_.erase(upstream);
        }
    }
    if (upstream != INVALID_SOCKET) {
        closesocket(upstream);
    }
    closesocket(client);
}

void TcpBrokerServer::Stop() noexcept {
    std::lock_guard<std::recursive_mutex> lifecycleLock(lifecycleMutex_);
    if (stopping_.exchange(true) && !winsockStarted_) {
        return;
    }

    // The accept thread owns the listener handles while it is in select()
    // or accept(). Signal it to leave first; closing a socket concurrently
    // with select() is not a reliable cancellation mechanism on Windows and
    // can race with SOCKET value reuse by an unrelated socket.
    if (acceptThread_.joinable()) {
        acceptThread_.join();
    }
    CloseSocket(ipv4Listener_);
    CloseSocket(ipv6Listener_);

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        for (SOCKET client : pendingClients_) {
            closesocket(client);
            sessionsInFlight_.fetch_sub(1);
        }
        pendingClients_.clear();
    }
    queueChanged_.notify_all();

    {
        std::lock_guard<std::mutex> lock(activeMutex_);
        for (SOCKET socket : activeSockets_) {
            shutdown(socket, SD_BOTH);
        }
    }

    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();

    ports_ = TcpBrokerListenerPorts{};
    socksAddressLength_ = 0;
    sessionsInFlight_.store(0);
    if (winsockStarted_) {
        WSACleanup();
        winsockStarted_ = false;
    }
}

bool TcpBrokerServer::IsRunning() const noexcept {
    std::lock_guard<std::recursive_mutex> lifecycleLock(lifecycleMutex_);
    return !stopping_.load();
}

bool TcpBrokerServer::IsConfiguredFor(
    const sockaddr* address,
    int addressLength) const noexcept {
    std::lock_guard<std::recursive_mutex> lifecycleLock(lifecycleMutex_);
    if (stopping_.load() || address == nullptr) {
        return false;
    }
    if (address->sa_family != socksAddress_.ss_family) {
        return false;
    }
    if (address->sa_family == AF_INET &&
        addressLength >= sizeof(sockaddr_in) &&
        socksAddressLength_ >= sizeof(sockaddr_in)) {
        const auto* requested = reinterpret_cast<const sockaddr_in*>(address);
        const auto* current = reinterpret_cast<const sockaddr_in*>(&socksAddress_);
        return requested->sin_port == current->sin_port &&
            requested->sin_addr.s_addr == current->sin_addr.s_addr;
    }
    if (address->sa_family == AF_INET6 &&
        addressLength >= sizeof(sockaddr_in6) &&
        socksAddressLength_ >= sizeof(sockaddr_in6)) {
        const auto* requested = reinterpret_cast<const sockaddr_in6*>(address);
        const auto* current = reinterpret_cast<const sockaddr_in6*>(&socksAddress_);
        return requested->sin6_port == current->sin6_port &&
            requested->sin6_scope_id == current->sin6_scope_id &&
            std::memcmp(&requested->sin6_addr, &current->sin6_addr,
                sizeof(IN6_ADDR)) == 0;
    }
    return false;
}

std::uint32_t TcpBrokerServer::ProcessId() const noexcept {
    return GetCurrentProcessId();
}

TcpBrokerListenerPorts TcpBrokerServer::ListenerPorts() const noexcept {
    std::lock_guard<std::recursive_mutex> lifecycleLock(lifecycleMutex_);
    return ports_;
}

} // namespace furious::wfp::broker
