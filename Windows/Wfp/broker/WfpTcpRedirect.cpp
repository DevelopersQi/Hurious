#include "WfpTcpRedirect.h"

#include <windows.h>
#include <mstcpip.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

namespace furious::wfp::broker {
namespace {

constexpr DWORD kMaximumOpaqueBlobSize = 64u * 1024u;
constexpr size_t kInitialOpaqueBlobSize = 1024u;
constexpr size_t kRelayBufferSize = 16u * 1024u;

int QueryOpaqueSocketOption(
    SOCKET socket,
    DWORD controlCode,
    std::vector<std::uint8_t>& output) noexcept {
    try {
        output.assign(kInitialOpaqueBlobSize, 0);
        for (;;) {
            DWORD bytesReturned = 0;
            const int result = WSAIoctl(
                socket, controlCode, nullptr, 0, output.data(),
                static_cast<DWORD>(output.size()), &bytesReturned,
                nullptr, nullptr);
            if (result == 0) {
                if (bytesReturned == 0 || bytesReturned > output.size()) {
                    return WSAEINVAL;
                }
                output.resize(bytesReturned);
                return 0;
            }

            const int error = WSAGetLastError();
            if (error != WSAEFAULT && error != WSAENOBUFS &&
                error != WSAEINVAL && error != ERROR_INSUFFICIENT_BUFFER) {
                return error;
            }
            if (bytesReturned <= output.size() ||
                bytesReturned > kMaximumOpaqueBlobSize) {
                return error;
            }
            output.resize(bytesReturned);
        }
    } catch (...) {
        output.clear();
        return WSA_NOT_ENOUGH_MEMORY;
    }
}

int SendAll(SOCKET socket, const std::uint8_t* data, size_t size) noexcept {
    size_t offset = 0;
    while (offset < size) {
        const int sent = send(
            socket, reinterpret_cast<const char*>(data + offset),
            static_cast<int>(std::min(
                size - offset,
                static_cast<size_t>((std::numeric_limits<int>::max)()))), 0);
        if (sent > 0) {
            offset += static_cast<size_t>(sent);
            continue;
        }
        if (sent == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (error == WSAEINTR) {
                continue;
            }
            return error;
        }
        return WSAECONNRESET;
    }
    return 0;
}

int ReceiveExact(SOCKET socket, std::uint8_t* data, size_t size) noexcept {
    size_t offset = 0;
    while (offset < size) {
        const int received = recv(
            socket, reinterpret_cast<char*>(data + offset),
            static_cast<int>(std::min(
                size - offset,
                static_cast<size_t>((std::numeric_limits<int>::max)()))), 0);
        if (received > 0) {
            offset += static_cast<size_t>(received);
            continue;
        }
        if (received == 0) {
            return WSAECONNRESET;
        }
        const int error = WSAGetLastError();
        if (error == WSAEINTR) {
            continue;
        }
        return error;
    }
    return 0;
}

int ReceiveSocks5Reply(SOCKET socket) noexcept {
    std::array<std::uint8_t, 4> header{};
    int error = ReceiveExact(socket, header.data(), header.size());
    if (error != 0) {
        return error;
    }
    if (header[0] != 0x05 || header[2] != 0x00 || header[1] != 0x00) {
        return header[1] == 0 ? WSAEPROTONOSUPPORT : WSAECONNREFUSED;
    }

    size_t addressSize = 0;
    switch (header[3]) {
    case 0x01:
        addressSize = 4;
        break;
    case 0x04:
        addressSize = 16;
        break;
    case 0x03: {
        std::uint8_t domainLength = 0;
        error = ReceiveExact(socket, &domainLength, sizeof(domainLength));
        if (error != 0) {
            return error;
        }
        addressSize = domainLength;
        break;
    }
    default:
        return WSAEPROTONOSUPPORT;
    }

    std::array<std::uint8_t, 257> tail{};
    return ReceiveExact(socket, tail.data(), addressSize + 2);
}

int SetNonblocking(SOCKET socket) noexcept {
    u_long enabled = 1;
    return ioctlsocket(socket, FIONBIO, &enabled) == 0
        ? 0 : WSAGetLastError();
}

int ConnectWithTimeout(
    SOCKET socket,
    const sockaddr* address,
    int addressLength,
    DWORD timeoutMilliseconds) noexcept {
    u_long nonblocking = 1;
    if (ioctlsocket(socket, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        return WSAGetLastError();
    }

    int error = 0;
    if (connect(socket, address, addressLength) == SOCKET_ERROR) {
        error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ||
            error == WSAEALREADY) {
            fd_set writable;
            fd_set exceptional;
            FD_ZERO(&writable);
            FD_ZERO(&exceptional);
            FD_SET(socket, &writable);
            FD_SET(socket, &exceptional);
            timeval timeout{
                static_cast<long>(timeoutMilliseconds / 1000u),
                static_cast<long>((timeoutMilliseconds % 1000u) * 1000u)
            };
            const int ready = select(
                0, nullptr, &writable, &exceptional, &timeout);
            if (ready == 0) {
                error = WSAETIMEDOUT;
            } else if (ready == SOCKET_ERROR) {
                error = WSAGetLastError();
            } else {
                int socketError = 0;
                int socketErrorLength = sizeof(socketError);
                if (getsockopt(
                        socket, SOL_SOCKET, SO_ERROR,
                        reinterpret_cast<char*>(&socketError),
                        &socketErrorLength) == SOCKET_ERROR) {
                    error = WSAGetLastError();
                } else {
                    error = socketError;
                }
            }
        }
    }

    u_long blocking = 0;
    if (ioctlsocket(socket, FIONBIO, &blocking) == SOCKET_ERROR &&
        error == 0) {
        error = WSAGetLastError();
    }
    return error;
}

int SendNonblocking(
    SOCKET socket,
    const char* data,
    size_t size,
    DWORD timeoutMilliseconds) noexcept {
    size_t offset = 0;
    const ULONGLONG deadline = GetTickCount64() + timeoutMilliseconds;
    while (offset < size) {
        // Enforce one absolute deadline across successful partial writes,
        // interrupted sends, and writable-socket waits.
        if (GetTickCount64() >= deadline) {
            return WSAETIMEDOUT;
        }
        const int sent = send(
            socket, data + offset,
            static_cast<int>(std::min(
                size - offset,
                static_cast<size_t>((std::numeric_limits<int>::max)()))), 0);
        if (sent > 0) {
            offset += static_cast<size_t>(sent);
            continue;
        }
        if (sent == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (error == WSAEINTR) {
                continue;
            }
            if (error != WSAEWOULDBLOCK) {
                return error;
            }

            const ULONGLONG now = GetTickCount64();
            if (now >= deadline) {
                return WSAETIMEDOUT;
            }
            const ULONGLONG remaining = deadline - now;
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(socket, &writable);
            timeval timeout{
                static_cast<long>(remaining / 1000u),
                static_cast<long>((remaining % 1000u) * 1000u)
            };
            const int ready = select(0, nullptr, &writable, nullptr, &timeout);
            if (ready == 0) {
                return WSAETIMEDOUT;
            }
            if (ready == SOCKET_ERROR) {
                return WSAGetLastError();
            }
            continue;
        }
        return WSAECONNRESET;
    }
    return 0;
}

} // namespace

int QueryRedirectedTcpConnection(
    SOCKET acceptedSocket,
    RedirectedTcpConnection& output) noexcept {
    output = RedirectedTcpConnection{};
    if (acceptedSocket == INVALID_SOCKET) {
        return WSAENOTSOCK;
    }

    int error = QueryOpaqueSocketOption(
        acceptedSocket, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
        output.redirectRecords);
    if (error != 0) {
        return error;
    }

    std::vector<std::uint8_t> contextBytes;
    error = QueryOpaqueSocketOption(
        acceptedSocket, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
        contextBytes);
    if (error != 0) {
        output.redirectRecords.clear();
        return error;
    }
    if (contextBytes.size() != sizeof(FURIOUS_WFP_REDIRECT_CONTEXT)) {
        output = RedirectedTcpConnection{};
        return WSAEPROTONOSUPPORT;
    }

    std::memcpy(&output.context, contextBytes.data(), sizeof(output.context));
    if (!furious::wfp::redirect::IsValidRedirectContext(output.context) ||
        output.context.Protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_TCP) {
        output = RedirectedTcpConnection{};
        return WSAEPROTONOSUPPORT;
    }

    if (output.context.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4) {
        auto* address = reinterpret_cast<sockaddr_in*>(&output.originalDestination);
        address->sin_family = AF_INET;
        address->sin_port = output.context.OriginalPortNetworkOrder;
        std::memcpy(&address->sin_addr, output.context.OriginalAddress, 4);
        output.originalDestinationLength = sizeof(sockaddr_in);
    } else {
        auto* address = reinterpret_cast<sockaddr_in6*>(&output.originalDestination);
        address->sin6_family = AF_INET6;
        address->sin6_port = output.context.OriginalPortNetworkOrder;
        std::memcpy(&address->sin6_addr, output.context.OriginalAddress, 16);
        output.originalDestinationLength = sizeof(sockaddr_in6);
    }
    return 0;
}

int ApplyRedirectRecords(
    SOCKET outboundSocket,
    const std::vector<std::uint8_t>& redirectRecords) noexcept {
    if (outboundSocket == INVALID_SOCKET || redirectRecords.empty() ||
        redirectRecords.size() > kMaximumOpaqueBlobSize) {
        return WSAEINVAL;
    }

    DWORD bytesReturned = 0;
    if (WSAIoctl(
            outboundSocket, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
            const_cast<std::uint8_t*>(redirectRecords.data()),
            static_cast<DWORD>(redirectRecords.size()),
            nullptr, 0, &bytesReturned, nullptr, nullptr) == SOCKET_ERROR) {
        return WSAGetLastError();
    }
    return 0;
}

bool BuildSocks5ConnectRequest(
    const FURIOUS_WFP_REDIRECT_CONTEXT& context,
    std::vector<std::uint8_t>& output) noexcept {
    output.clear();
    if (!furious::wfp::redirect::IsValidRedirectContext(context) ||
        context.Protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_TCP) {
        return false;
    }

    try {
        if (context.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4) {
            output.reserve(10);
            output.insert(output.end(), {0x05, 0x01, 0x00, 0x01});
            output.insert(output.end(), context.OriginalAddress,
                context.OriginalAddress + 4);
        } else {
            output.reserve(22);
            output.insert(output.end(), {0x05, 0x01, 0x00, 0x04});
            output.insert(output.end(), context.OriginalAddress,
                context.OriginalAddress + 16);
        }
        const auto* port = reinterpret_cast<const std::uint8_t*>(
            &context.OriginalPortNetworkOrder);
        output.push_back(port[0]);
        output.push_back(port[1]);
        return true;
    } catch (...) {
        output.clear();
        return false;
    }
}

SOCKET OpenSocks5Tunnel(
    const sockaddr* socksAddress,
    int socksAddressLength,
    const RedirectedTcpConnection& redirected,
    int* errorCode,
    ActiveSocketRegister registerSocket,
    ActiveSocketUnregister unregisterSocket,
    void* callbackContext) noexcept {
    if (errorCode != nullptr) {
        *errorCode = 0;
    }
    const int requiredAddressLength = socksAddress != nullptr &&
        socksAddress->sa_family == AF_INET ? sizeof(sockaddr_in) :
        socksAddress != nullptr && socksAddress->sa_family == AF_INET6
            ? sizeof(sockaddr_in6) : 0;
    if (requiredAddressLength == 0 ||
        socksAddressLength < requiredAddressLength ||
        redirected.redirectRecords.empty() ||
        ((registerSocket == nullptr) != (unregisterSocket == nullptr)) ||
        !furious::wfp::redirect::IsValidRedirectContext(redirected.context) ||
        redirected.context.Protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_TCP) {
        if (errorCode != nullptr) {
            *errorCode = WSAEINVAL;
        }
        return INVALID_SOCKET;
    }

    SOCKET upstream = socket(socksAddress->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (upstream == INVALID_SOCKET) {
        if (errorCode != nullptr) {
            *errorCode = WSAGetLastError();
        }
        return INVALID_SOCKET;
    }

    // Publish the socket before connect/handshake so Stop() can shutdown it
    // from another thread. Registration is atomic with the server's stopping
    // check; a late worker is rejected instead of escaping cancellation.
    if (registerSocket != nullptr &&
        !registerSocket(callbackContext, upstream)) {
        closesocket(upstream);
        if (errorCode != nullptr) *errorCode = WSA_OPERATION_ABORTED;
        return INVALID_SOCKET;
    }

    DWORD handshakeTimeout = 3000;
    if (setsockopt(upstream, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&handshakeTimeout),
            sizeof(handshakeTimeout)) == SOCKET_ERROR ||
        setsockopt(upstream, SOL_SOCKET, SO_SNDTIMEO,
            reinterpret_cast<const char*>(&handshakeTimeout),
            sizeof(handshakeTimeout)) == SOCKET_ERROR) {
        const int socketError = WSAGetLastError();
        if (unregisterSocket != nullptr) {
            unregisterSocket(callbackContext, upstream);
        }
        closesocket(upstream);
        if (errorCode != nullptr) *errorCode = socketError;
        return INVALID_SOCKET;
    }

    int error = ApplyRedirectRecords(upstream, redirected.redirectRecords);
    if (error == 0) {
        error = ConnectWithTimeout(
            upstream, socksAddress, socksAddressLength, 5000);
    }

    const std::uint8_t greeting[] = {0x05, 0x01, 0x00};
    std::array<std::uint8_t, 2> greetingReply{};
    if (error == 0) {
        error = SendAll(upstream, greeting, sizeof(greeting));
    }
    if (error == 0) {
        error = ReceiveExact(upstream, greetingReply.data(), greetingReply.size());
        if (error == 0 &&
            (greetingReply[0] != 0x05 || greetingReply[1] != 0x00)) {
            error = WSAEACCES;
        }
    }

    std::vector<std::uint8_t> request;
    if (error == 0 && !BuildSocks5ConnectRequest(redirected.context, request)) {
        error = WSAEINVAL;
    }
    if (error == 0) {
        error = SendAll(upstream, request.data(), request.size());
    }
    if (error == 0) {
        error = ReceiveSocks5Reply(upstream);
    }

    if (error != 0) {
        if (unregisterSocket != nullptr) {
            unregisterSocket(callbackContext, upstream);
        }
        closesocket(upstream);
        if (errorCode != nullptr) {
            *errorCode = error;
        }
        return INVALID_SOCKET;
    }
    return upstream;
}

int RelayBidirectional(
    SOCKET clientSocket,
    SOCKET upstreamSocket,
    DWORD idleTimeoutMilliseconds) noexcept {
    if (clientSocket == INVALID_SOCKET || upstreamSocket == INVALID_SOCKET) {
        return WSAENOTSOCK;
    }

    int error = SetNonblocking(clientSocket);
    if (error == 0) {
        error = SetNonblocking(upstreamSocket);
    }
    if (error != 0) {
        return error;
    }

    bool clientReadClosed = false;
    bool upstreamReadClosed = false;
    std::array<char, kRelayBufferSize> buffer{};
    ULONGLONG lastActivity = GetTickCount64();

    while (!clientReadClosed || !upstreamReadClosed) {
        fd_set readable;
        FD_ZERO(&readable);
        if (!clientReadClosed) {
            FD_SET(clientSocket, &readable);
        }
        if (!upstreamReadClosed) {
            FD_SET(upstreamSocket, &readable);
        }
        timeval timeout{1, 0};
        const int ready = select(0, &readable, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR) {
            return WSAGetLastError();
        }
        if (ready == 0) {
            if (GetTickCount64() - lastActivity >= idleTimeoutMilliseconds) {
                return WSAETIMEDOUT;
            }
            continue;
        }

        const SOCKET sources[] = {clientSocket, upstreamSocket};
        for (SOCKET source : sources) {
            if (!FD_ISSET(source, &readable)) {
                continue;
            }
            const int received = recv(
                source, buffer.data(), static_cast<int>(buffer.size()), 0);
            if (received == 0) {
                if (source == clientSocket) {
                    clientReadClosed = true;
                    shutdown(upstreamSocket, SD_SEND);
                } else {
                    upstreamReadClosed = true;
                    shutdown(clientSocket, SD_SEND);
                }
                continue;
            }
            if (received == SOCKET_ERROR) {
                const int receiveError = WSAGetLastError();
                if (receiveError == WSAEWOULDBLOCK || receiveError == WSAEINTR) {
                    continue;
                }
                return receiveError;
            }

            const SOCKET destination =
                source == clientSocket ? upstreamSocket : clientSocket;
            error = SendNonblocking(
                destination, buffer.data(), static_cast<size_t>(received),
                idleTimeoutMilliseconds);
            if (error != 0) {
                return error;
            }
            lastActivity = GetTickCount64();
        }
    }
    return 0;
}

} // namespace furious::wfp::broker
