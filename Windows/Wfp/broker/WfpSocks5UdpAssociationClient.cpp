#include "WfpSocks5UdpAssociationClient.h"

#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace furious::wfp::broker {
namespace {

bool IsLoopbackAddress(const sockaddr* address) noexcept {
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
            const int ready = select(0, nullptr, &writable, &exceptional, &timeout);
            if (ready == 0) {
                error = WSAETIMEDOUT;
            } else if (ready == SOCKET_ERROR) {
                error = WSAGetLastError();
            } else {
                int socketError = 0;
                int socketErrorLength = sizeof(socketError);
                if (getsockopt(socket, SOL_SOCKET, SO_ERROR,
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
    if (ioctlsocket(socket, FIONBIO, &blocking) == SOCKET_ERROR && error == 0) {
        error = WSAGetLastError();
    }
    return error;
}

int SendAll(SOCKET socket, const std::uint8_t* data, std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        const int chunk = static_cast<int>(std::min(
            length - offset, static_cast<std::size_t>((std::numeric_limits<int>::max)())));
        const int sent = send(socket,
            reinterpret_cast<const char*>(data + offset), chunk, 0);
        if (sent > 0) {
            offset += static_cast<std::size_t>(sent);
            continue;
        }
        if (sent == SOCKET_ERROR) {
            const int error = WSAGetLastError();
            if (error == WSAEINTR) continue;
            return error;
        }
        return WSAECONNRESET;
    }
    return 0;
}

int ReceiveExact(SOCKET socket, std::uint8_t* data, std::size_t length) noexcept {
    std::size_t offset = 0;
    while (offset < length) {
        const int chunk = static_cast<int>(std::min(
            length - offset, static_cast<std::size_t>((std::numeric_limits<int>::max)())));
        const int received = recv(socket,
            reinterpret_cast<char*>(data + offset), chunk, 0);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
            continue;
        }
        if (received == 0) return WSAECONNRESET;
        const int error = WSAGetLastError();
        if (error == WSAEINTR) continue;
        return error;
    }
    return 0;
}

int ReceiveAssociateReply(
    SOCKET socket,
    std::vector<std::uint8_t>& reply) noexcept {
    reply.clear();
    std::array<std::uint8_t, 4> header{};
    int error = ReceiveExact(socket, header.data(), header.size());
    if (error != 0) return error;

    std::size_t addressLength = 0;
    switch (header[3]) {
    case 0x01:
        addressLength = 4;
        break;
    case 0x04:
        addressLength = 16;
        break;
    case 0x03: {
        std::uint8_t domainLength = 0;
        error = ReceiveExact(socket, &domainLength, sizeof(domainLength));
        if (error != 0) return error;
        addressLength = domainLength;
        break;
    }
    default:
        try {
            reply.assign(header.begin(), header.end());
        } catch (...) {
            reply.clear();
            return WSA_NOT_ENOUGH_MEMORY;
        }
        return 0;
    }

    try {
        reply.assign(header.begin(), header.end());
        if (header[3] == 0x03) {
            std::uint8_t domainLength = static_cast<std::uint8_t>(addressLength);
            reply.push_back(domainLength);
        }
        const std::size_t oldSize = reply.size();
        reply.resize(oldSize + addressLength + 2);
    } catch (...) {
        reply.clear();
        return WSA_NOT_ENOUGH_MEMORY;
    }
    return ReceiveExact(socket, reply.data() + reply.size() - addressLength - 2,
        addressLength + 2);
}

bool BuildRelayEndpoint(
    const sockaddr* socksAddress,
    const Socks5UdpAssociateReplyView& reply,
    sockaddr_storage& output,
    int& outputLength) noexcept {
    output = sockaddr_storage{};
    outputLength = 0;
    if (socksAddress->sa_family == AF_INET &&
        reply.addressType == Socks5UdpAddressType::Ipv4 &&
        reply.addressLength == 4) {
        auto* endpoint = reinterpret_cast<sockaddr_in*>(&output);
        endpoint->sin_family = AF_INET;
        endpoint->sin_port = htons(reply.port);
        std::memcpy(&endpoint->sin_addr, reply.address, 4);
        if (endpoint->sin_addr.s_addr == htonl(INADDR_ANY)) {
            endpoint->sin_addr =
                reinterpret_cast<const sockaddr_in*>(socksAddress)->sin_addr;
        }
        if ((ntohl(endpoint->sin_addr.s_addr) & 0xFF000000u) != 0x7F000000u) {
            return false;
        }
        outputLength = sizeof(sockaddr_in);
        return true;
    }
    if (socksAddress->sa_family == AF_INET6 &&
        reply.addressType == Socks5UdpAddressType::Ipv6 &&
        reply.addressLength == 16) {
        auto* endpoint = reinterpret_cast<sockaddr_in6*>(&output);
        endpoint->sin6_family = AF_INET6;
        endpoint->sin6_port = htons(reply.port);
        std::memcpy(&endpoint->sin6_addr, reply.address, 16);
        if (IN6_IS_ADDR_UNSPECIFIED(&endpoint->sin6_addr)) {
            endpoint->sin6_addr =
                reinterpret_cast<const sockaddr_in6*>(socksAddress)->sin6_addr;
        }
        if (!IN6_IS_ADDR_LOOPBACK(&endpoint->sin6_addr)) return false;
        outputLength = sizeof(sockaddr_in6);
        return true;
    }
    return false;
}

} // namespace

Socks5UdpAssociationClient::~Socks5UdpAssociationClient() {
    Close();
}

Socks5UdpAssociationClientOpenResult Socks5UdpAssociationClient::Open(
    const sockaddr* socksAddress,
    int socksAddressLength,
    const Socks5UdpSocket& localUdpSocket,
    DWORD timeoutMilliseconds,
    int* errorCode,
    ActiveSocketRegister registerSocket,
    ActiveSocketUnregister unregisterSocket,
    void* callbackContext) noexcept {
    if (errorCode != nullptr) *errorCode = 0;
    if (controlSocket_ != INVALID_SOCKET) {
        return Socks5UdpAssociationClientOpenResult::AlreadyOpen;
    }
    if (socksAddress == nullptr || !IsLoopbackAddress(socksAddress) ||
        !localUdpSocket.IsOpen() || localUdpSocket.LocalPort() == 0 ||
        timeoutMilliseconds == 0 ||
        ((registerSocket == nullptr) != (unregisterSocket == nullptr))) {
        if (errorCode != nullptr) *errorCode = WSAEINVAL;
        return Socks5UdpAssociationClientOpenResult::InvalidArgument;
    }
    const int expectedLength = socksAddress->sa_family == AF_INET
        ? sizeof(sockaddr_in)
        : socksAddress->sa_family == AF_INET6
            ? sizeof(sockaddr_in6) : 0;
    const auto expectedUdpFamily = socksAddress->sa_family == AF_INET
        ? Socks5UdpEndpointFamily::Ipv4 : Socks5UdpEndpointFamily::Ipv6;
    if (expectedLength == 0 || socksAddressLength < expectedLength ||
        localUdpSocket.Family() != expectedUdpFamily) {
        if (errorCode != nullptr) *errorCode = WSAEAFNOSUPPORT;
        return Socks5UdpAssociationClientOpenResult::InvalidArgument;
    }
    const std::uint16_t socksPort = socksAddress->sa_family == AF_INET
        ? ntohs(reinterpret_cast<const sockaddr_in*>(socksAddress)->sin_port)
        : ntohs(reinterpret_cast<const sockaddr_in6*>(socksAddress)->sin6_port);
    if (socksPort == 0) {
        if (errorCode != nullptr) *errorCode = WSAEINVAL;
        return Socks5UdpAssociationClientOpenResult::InvalidArgument;
    }

    controlSocket_ = socket(socksAddress->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (controlSocket_ == INVALID_SOCKET) {
        if (errorCode != nullptr) *errorCode = WSAGetLastError();
        return Socks5UdpAssociationClientOpenResult::SocketCreationFailed;
    }
    if (registerSocket != nullptr) {
        if (!registerSocket(callbackContext, controlSocket_)) {
            closesocket(controlSocket_);
            controlSocket_ = INVALID_SOCKET;
            if (errorCode != nullptr) *errorCode = WSA_OPERATION_ABORTED;
            return Socks5UdpAssociationClientOpenResult::RegistrationFailed;
        }
        registered_ = true;
        unregisterSocket_ = unregisterSocket;
        callbackContext_ = callbackContext;
    }

    const auto fail = [this, errorCode](
        Socks5UdpAssociationClientOpenResult result, int error) noexcept {
        if (errorCode != nullptr) *errorCode = error;
        Close();
        return result;
    };

    if (setsockopt(controlSocket_, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&timeoutMilliseconds),
            sizeof(timeoutMilliseconds)) == SOCKET_ERROR ||
        setsockopt(controlSocket_, SOL_SOCKET, SO_SNDTIMEO,
            reinterpret_cast<const char*>(&timeoutMilliseconds),
            sizeof(timeoutMilliseconds)) == SOCKET_ERROR) {
        return fail(Socks5UdpAssociationClientOpenResult::SocketOptionFailed,
            WSAGetLastError());
    }

    int error = ConnectWithTimeout(controlSocket_, socksAddress,
        expectedLength, timeoutMilliseconds);
    if (error != 0) {
        return fail(Socks5UdpAssociationClientOpenResult::ConnectFailed, error);
    }

    const std::uint8_t greeting[] = {0x05, 0x01, 0x00};
    error = SendAll(controlSocket_, greeting, sizeof(greeting));
    if (error != 0) {
        return fail(Socks5UdpAssociationClientOpenResult::MethodRejected, error);
    }
    std::array<std::uint8_t, 2> greetingReply{};
    error = ReceiveExact(controlSocket_, greetingReply.data(), greetingReply.size());
    if (error != 0 || greetingReply[0] != 0x05 || greetingReply[1] != 0x00) {
        return fail(Socks5UdpAssociationClientOpenResult::MethodRejected,
            error != 0 ? error : WSAEACCES);
    }

    std::array<std::uint8_t, 22> request{};
    std::size_t requestLength = 0;
    const std::uint16_t localPort = localUdpSocket.LocalPort();
    if (socksAddress->sa_family == AF_INET) {
        const std::uint8_t requestBytes[] = {
            0x05, 0x03, 0x00, 0x01, 127, 0, 0, 1,
            static_cast<std::uint8_t>(localPort >> 8),
            static_cast<std::uint8_t>(localPort & 0xFF)
        };
        std::memcpy(request.data(), requestBytes, sizeof(requestBytes));
        requestLength = sizeof(requestBytes);
    } else {
        request[0] = 0x05;
        request[1] = 0x03;
        request[2] = 0x00;
        request[3] = 0x04;
        request[19] = 1; // ::1
        request[20] = static_cast<std::uint8_t>(localPort >> 8);
        request[21] = static_cast<std::uint8_t>(localPort & 0xFF);
        requestLength = request.size();
    }
    error = SendAll(controlSocket_, request.data(), requestLength);
    if (error != 0) {
        return fail(Socks5UdpAssociationClientOpenResult::RequestFailed, error);
    }

    std::vector<std::uint8_t> replyBytes;
    error = ReceiveAssociateReply(controlSocket_, replyBytes);
    if (error != 0) {
        return fail(Socks5UdpAssociationClientOpenResult::ReplyRejected, error);
    }
    Socks5UdpAssociateReplyView reply{};
    if (ParseSocks5UdpAssociateReply(replyBytes.data(), replyBytes.size(), reply) !=
        Socks5UdpAssociateReplyResult::Valid) {
        return fail(Socks5UdpAssociationClientOpenResult::ReplyRejected,
            reply.replyCode == 0 ? WSAEPROTONOSUPPORT : WSAECONNREFUSED);
    }
    if (!BuildRelayEndpoint(socksAddress, reply,
            relayAddress_, relayAddressLength_)) {
        return fail(Socks5UdpAssociationClientOpenResult::UnsupportedRelayEndpoint,
            WSAEAFNOSUPPORT);
    }

    u_long nonblocking = 1;
    if (ioctlsocket(controlSocket_, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        return fail(Socks5UdpAssociationClientOpenResult::NonblockingFailed,
            WSAGetLastError());
    }
    return Socks5UdpAssociationClientOpenResult::Opened;
}

void Socks5UdpAssociationClient::Close() noexcept {
    if (controlSocket_ != INVALID_SOCKET) {
        if (registered_ && unregisterSocket_ != nullptr) {
            unregisterSocket_(callbackContext_, controlSocket_);
        }
        registered_ = false;
        unregisterSocket_ = nullptr;
        callbackContext_ = nullptr;
        shutdown(controlSocket_, SD_BOTH);
        closesocket(controlSocket_);
        controlSocket_ = INVALID_SOCKET;
    }
    relayAddress_ = sockaddr_storage{};
    relayAddressLength_ = 0;
}

bool Socks5UdpAssociationClient::IsOpen() const noexcept {
    return controlSocket_ != INVALID_SOCKET && relayAddressLength_ != 0;
}

bool Socks5UdpAssociationClient::IsControlAlive() const noexcept {
    if (controlSocket_ == INVALID_SOCKET) return false;
    char byte = 0;
    const int result = recv(controlSocket_, &byte, 1, MSG_PEEK);
    if (result == 0) return false;
    if (result > 0) return false; // The control channel is reserved for lifetime.
    const int error = WSAGetLastError();
    return error == WSAEWOULDBLOCK || error == WSAEINTR;
}

SOCKET Socks5UdpAssociationClient::ControlSocket() const noexcept {
    return controlSocket_;
}

const sockaddr* Socks5UdpAssociationClient::RelayAddress() const noexcept {
    return relayAddressLength_ == 0
        ? nullptr : reinterpret_cast<const sockaddr*>(&relayAddress_);
}

int Socks5UdpAssociationClient::RelayAddressLength() const noexcept {
    return relayAddressLength_;
}

} // namespace furious::wfp::broker
