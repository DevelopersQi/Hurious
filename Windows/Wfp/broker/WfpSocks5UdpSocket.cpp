#include "WfpSocks5UdpSocket.h"

#include <ws2tcpip.h>

namespace furious::wfp::broker {

Socks5UdpSocket::~Socks5UdpSocket() {
    Close();
}

Socks5UdpSocketOpenResult Socks5UdpSocket::Open(
    Socks5UdpEndpointFamily family,
    int* errorCode) noexcept {
    if (errorCode != nullptr) *errorCode = 0;
    if (socket_ != INVALID_SOCKET) return Socks5UdpSocketOpenResult::AlreadyOpen;

    int addressFamily = AF_UNSPEC;
    if (family == Socks5UdpEndpointFamily::Ipv4) {
        addressFamily = AF_INET;
    } else if (family == Socks5UdpEndpointFamily::Ipv6) {
        addressFamily = AF_INET6;
    } else {
        if (errorCode != nullptr) *errorCode = WSAEAFNOSUPPORT;
        return Socks5UdpSocketOpenResult::UnsupportedAddressFamily;
    }

    const auto fail = [this, errorCode](Socks5UdpSocketOpenResult result,
        int error) noexcept {
        Close();
        if (errorCode != nullptr) *errorCode = error;
        return result;
    };

    socket_ = socket(addressFamily, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == INVALID_SOCKET) {
        return fail(Socks5UdpSocketOpenResult::SocketCreationFailed, WSAGetLastError());
    }

    BOOL exclusive = TRUE;
    if (setsockopt(socket_, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&exclusive), sizeof(exclusive)) == SOCKET_ERROR) {
        return fail(Socks5UdpSocketOpenResult::SocketOptionFailed, WSAGetLastError());
    }

    const int bufferBytes = kSocks5UdpSocketBufferBytes;
    if (setsockopt(socket_, SOL_SOCKET, SO_RCVBUF,
            reinterpret_cast<const char*>(&bufferBytes), sizeof(bufferBytes)) == SOCKET_ERROR ||
        setsockopt(socket_, SOL_SOCKET, SO_SNDBUF,
            reinterpret_cast<const char*>(&bufferBytes), sizeof(bufferBytes)) == SOCKET_ERROR) {
        return fail(Socks5UdpSocketOpenResult::SocketOptionFailed, WSAGetLastError());
    }

    if (addressFamily == AF_INET) {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        address.sin_port = 0;
        if (bind(socket_, reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) == SOCKET_ERROR) {
            return fail(Socks5UdpSocketOpenResult::BindFailed, WSAGetLastError());
        }
        int length = sizeof(address);
        if (getsockname(socket_, reinterpret_cast<sockaddr*>(&address),
                &length) == SOCKET_ERROR) {
            return fail(Socks5UdpSocketOpenResult::QueryBoundPortFailed, WSAGetLastError());
        }
        if (ntohs(address.sin_port) == 0) {
            return fail(Socks5UdpSocketOpenResult::QueryBoundPortFailed, WSAEINVAL);
        }
        localPort_ = ntohs(address.sin_port);
    } else {
        DWORD onlyV6 = 1;
        if (setsockopt(socket_, IPPROTO_IPV6, IPV6_V6ONLY,
                reinterpret_cast<const char*>(&onlyV6), sizeof(onlyV6)) == SOCKET_ERROR) {
            return fail(Socks5UdpSocketOpenResult::SocketOptionFailed, WSAGetLastError());
        }
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6;
        address.sin6_addr = in6addr_any;
        address.sin6_port = 0;
        if (bind(socket_, reinterpret_cast<const sockaddr*>(&address),
                sizeof(address)) == SOCKET_ERROR) {
            return fail(Socks5UdpSocketOpenResult::BindFailed, WSAGetLastError());
        }
        int length = sizeof(address);
        if (getsockname(socket_, reinterpret_cast<sockaddr*>(&address),
                &length) == SOCKET_ERROR) {
            return fail(Socks5UdpSocketOpenResult::QueryBoundPortFailed, WSAGetLastError());
        }
        if (ntohs(address.sin6_port) == 0) {
            return fail(Socks5UdpSocketOpenResult::QueryBoundPortFailed, WSAEINVAL);
        }
        localPort_ = ntohs(address.sin6_port);
    }

    u_long nonblocking = 1;
    if (ioctlsocket(socket_, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        return fail(Socks5UdpSocketOpenResult::NonblockingFailed, WSAGetLastError());
    }

    family_ = family;
    return Socks5UdpSocketOpenResult::Opened;
}

void Socks5UdpSocket::Close() noexcept {
    if (socket_ != INVALID_SOCKET) {
        closesocket(socket_);
        socket_ = INVALID_SOCKET;
    }
    localPort_ = 0;
}

bool Socks5UdpSocket::IsOpen() const noexcept {
    return socket_ != INVALID_SOCKET;
}

SOCKET Socks5UdpSocket::NativeHandle() const noexcept {
    return socket_;
}

Socks5UdpEndpointFamily Socks5UdpSocket::Family() const noexcept {
    return family_;
}

std::uint16_t Socks5UdpSocket::LocalPort() const noexcept {
    return localPort_;
}

} // namespace furious::wfp::broker
