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
    asyncState_ = Socks5UdpAssociationAsyncState::Ready;
    return Socks5UdpAssociationClientOpenResult::Opened;
}


Socks5UdpAssociationAsyncResult Socks5UdpAssociationClient::BeginOpen(
    const sockaddr* socksAddress, int socksAddressLength,
    const Socks5UdpSocket& localUdpSocket, DWORD timeoutMilliseconds,
    int* errorCode, ActiveSocketRegister registerSocket,
    ActiveSocketUnregister unregisterSocket, void* callbackContext) noexcept {
    if (errorCode != nullptr) *errorCode = 0;
    if (controlSocket_ != INVALID_SOCKET ||
        asyncState_ != Socks5UdpAssociationAsyncState::Idle) {
        if (errorCode != nullptr) *errorCode = WSAEALREADY;
        return Socks5UdpAssociationAsyncResult::AlreadyStarted;
    }
    if (socksAddress == nullptr || !IsLoopbackAddress(socksAddress) ||
        !localUdpSocket.IsOpen() || localUdpSocket.LocalPort() == 0 ||
        timeoutMilliseconds == 0 ||
        ((registerSocket == nullptr) != (unregisterSocket == nullptr))) {
        if (errorCode != nullptr) *errorCode = WSAEINVAL;
        return Socks5UdpAssociationAsyncResult::InvalidArgument;
    }
    const int expectedLength = socksAddress->sa_family == AF_INET
        ? sizeof(sockaddr_in)
        : socksAddress->sa_family == AF_INET6 ? sizeof(sockaddr_in6) : 0;
    const auto expectedFamily = socksAddress->sa_family == AF_INET
        ? Socks5UdpEndpointFamily::Ipv4 : Socks5UdpEndpointFamily::Ipv6;
    if (expectedLength == 0 || socksAddressLength < expectedLength ||
        localUdpSocket.Family() != expectedFamily) {
        if (errorCode != nullptr) *errorCode = WSAEAFNOSUPPORT;
        return Socks5UdpAssociationAsyncResult::InvalidArgument;
    }
    const std::uint16_t socksPort = socksAddress->sa_family == AF_INET
        ? ntohs(reinterpret_cast<const sockaddr_in*>(socksAddress)->sin_port)
        : ntohs(reinterpret_cast<const sockaddr_in6*>(socksAddress)->sin6_port);
    if (socksPort == 0) {
        if (errorCode != nullptr) *errorCode = WSAEINVAL;
        return Socks5UdpAssociationAsyncResult::InvalidArgument;
    }

    controlSocket_ = socket(socksAddress->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (controlSocket_ == INVALID_SOCKET) {
        const int error = WSAGetLastError();
        if (errorCode != nullptr) *errorCode = error;
        asyncState_ = Socks5UdpAssociationAsyncState::Failed;
        asyncError_ = error;
        return Socks5UdpAssociationAsyncResult::Failed;
    }
    if (registerSocket != nullptr) {
        if (!registerSocket(callbackContext, controlSocket_)) {
            closesocket(controlSocket_);
            controlSocket_ = INVALID_SOCKET;
            if (errorCode != nullptr) *errorCode = WSA_OPERATION_ABORTED;
            asyncState_ = Socks5UdpAssociationAsyncState::Failed;
            asyncError_ = WSA_OPERATION_ABORTED;
            return Socks5UdpAssociationAsyncResult::Failed;
        }
        registered_ = true;
        unregisterSocket_ = unregisterSocket;
        callbackContext_ = callbackContext;
    }
    u_long nonblocking = 1;
    if (ioctlsocket(controlSocket_, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        if (errorCode != nullptr) *errorCode = error;
        Close();
        asyncState_ = Socks5UdpAssociationAsyncState::Failed;
        asyncError_ = error;
        return Socks5UdpAssociationAsyncResult::Failed;
    }
    std::memcpy(&socksAddress_, socksAddress, static_cast<std::size_t>(expectedLength));
    socksAddressLength_ = expectedLength;
    asyncDeadline_ = GetTickCount64() + timeoutMilliseconds;
    asyncRequestLength_ = 0;
    asyncSendOffset_ = 0;
    asyncReplySize_ = 0;
    asyncReplyExpected_ = 4;
    asyncError_ = 0;

    if (socksAddress->sa_family == AF_INET) {
        const std::uint16_t port = localUdpSocket.LocalPort();
        const std::uint8_t request[] = {5, 3, 0, 1, 127, 0, 0, 1,
            static_cast<std::uint8_t>(port >> 8), static_cast<std::uint8_t>(port)};
        std::memcpy(asyncRequest_.data(), request, sizeof(request));
        asyncRequestLength_ = sizeof(request);
    } else {
        const std::uint16_t port = localUdpSocket.LocalPort();
        asyncRequest_.fill(0);
        asyncRequest_[0] = 5; asyncRequest_[1] = 3; asyncRequest_[2] = 0;
        asyncRequest_[3] = 4; asyncRequest_[19] = 1;
        asyncRequest_[20] = static_cast<std::uint8_t>(port >> 8);
        asyncRequest_[21] = static_cast<std::uint8_t>(port);
        asyncRequestLength_ = 22;
    }

    const int connectResult = connect(controlSocket_, socksAddress, expectedLength);
    if (connectResult == 0) {
        asyncState_ = Socks5UdpAssociationAsyncState::SendingGreeting;
    } else {
        const int error = WSAGetLastError();
        if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ||
            error == WSAEALREADY) {
            asyncState_ = Socks5UdpAssociationAsyncState::Connecting;
        } else {
            if (errorCode != nullptr) *errorCode = error;
            Close();
            asyncState_ = Socks5UdpAssociationAsyncState::Failed;
            asyncError_ = error;
            return Socks5UdpAssociationAsyncResult::Failed;
        }
    }
    return Socks5UdpAssociationAsyncResult::Pending;
}

Socks5UdpAssociationAsyncResult Socks5UdpAssociationClient::Advance(
    bool readable, bool writable, int* errorCode) noexcept {
    if (errorCode != nullptr) *errorCode = 0;
    if (asyncState_ == Socks5UdpAssociationAsyncState::Ready)
        return Socks5UdpAssociationAsyncResult::Ready;
    if (asyncState_ == Socks5UdpAssociationAsyncState::Failed) {
        if (errorCode != nullptr) *errorCode = asyncError_;
        return Socks5UdpAssociationAsyncResult::Failed;
    }
    if (asyncState_ == Socks5UdpAssociationAsyncState::Idle)
        return Socks5UdpAssociationAsyncResult::InvalidArgument;
    if (GetTickCount64() >= asyncDeadline_) {
        asyncError_ = WSAETIMEDOUT;
        Close();
        asyncState_ = Socks5UdpAssociationAsyncState::Failed;
        asyncError_ = WSAETIMEDOUT;
        if (errorCode != nullptr) *errorCode = asyncError_;
        return Socks5UdpAssociationAsyncResult::Failed;
    }

    const auto fail = [this, errorCode](int error) noexcept {
        asyncError_ = error == 0 ? WSAECONNRESET : error;
        Close();
        asyncState_ = Socks5UdpAssociationAsyncState::Failed;
        if (errorCode != nullptr) *errorCode = asyncError_;
        return Socks5UdpAssociationAsyncResult::Failed;
    };

    for (unsigned transitions = 0; transitions < 8; ++transitions) {
        if (asyncState_ == Socks5UdpAssociationAsyncState::Connecting) {
            if (!readable && !writable) return Socks5UdpAssociationAsyncResult::Pending;
            int socketError = 0, length = sizeof(socketError);
            if (getsockopt(controlSocket_, SOL_SOCKET, SO_ERROR,
                    reinterpret_cast<char*>(&socketError), &length) == SOCKET_ERROR)
                return fail(WSAGetLastError());
            if (socketError != 0) return fail(socketError);
            asyncState_ = Socks5UdpAssociationAsyncState::SendingGreeting;
            continue;
        }
        if (asyncState_ == Socks5UdpAssociationAsyncState::SendingGreeting ||
            asyncState_ == Socks5UdpAssociationAsyncState::SendingAssociateRequest) {
            if (!writable) return Socks5UdpAssociationAsyncResult::Pending;
            const std::uint8_t greeting[] = {5, 1, 0};
            const std::uint8_t* bytes = asyncState_ == Socks5UdpAssociationAsyncState::SendingGreeting
                ? greeting : asyncRequest_.data();
            const std::size_t length = asyncState_ == Socks5UdpAssociationAsyncState::SendingGreeting
                ? sizeof(greeting) : asyncRequestLength_;
            const int sent = send(controlSocket_,
                reinterpret_cast<const char*>(bytes + asyncSendOffset_),
                static_cast<int>(length - asyncSendOffset_), 0);
            if (sent == SOCKET_ERROR) {
                const int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK || error == WSAEINTR)
                    return Socks5UdpAssociationAsyncResult::Pending;
                return fail(error);
            }
            if (sent == 0) return fail(WSAECONNRESET);
            asyncSendOffset_ += static_cast<std::size_t>(sent);
            if (asyncSendOffset_ < length) return Socks5UdpAssociationAsyncResult::Pending;
            asyncSendOffset_ = 0;
            if (asyncState_ == Socks5UdpAssociationAsyncState::SendingGreeting)
                asyncState_ = Socks5UdpAssociationAsyncState::ReceivingMethod;
            else {
                asyncState_ = Socks5UdpAssociationAsyncState::ReceivingAssociateReply;
                asyncReplySize_ = 0;
                asyncReplyExpected_ = 4;
            }
            continue;
        }
        if (asyncState_ == Socks5UdpAssociationAsyncState::ReceivingMethod) {
            if (!readable) return Socks5UdpAssociationAsyncResult::Pending;
            std::uint8_t method[2]{};
            const int received = recv(controlSocket_, reinterpret_cast<char*>(method), 2, 0);
            if (received == SOCKET_ERROR) {
                const int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK || error == WSAEINTR)
                    return Socks5UdpAssociationAsyncResult::Pending;
                return fail(error);
            }
            if (received == 0) return fail(WSAECONNRESET);
            if (received != 2) {
                // Keep protocol reads atomic by buffering a split method reply.
                asyncReply_[asyncReplySize_++] = method[0];
                asyncState_ = Socks5UdpAssociationAsyncState::ReceivingMethod;
                return Socks5UdpAssociationAsyncResult::Pending;
            }
            if (method[0] != 5 || method[1] != 0) return fail(WSAEACCES);
            asyncState_ = Socks5UdpAssociationAsyncState::SendingAssociateRequest;
            asyncSendOffset_ = 0;
            continue;
        }
        if (asyncState_ == Socks5UdpAssociationAsyncState::ReceivingAssociateReply) {
            if (!readable) return Socks5UdpAssociationAsyncResult::Pending;
            std::size_t target = asyncReplyExpected_ - asyncReplySize_;
            const int received = recv(controlSocket_,
                reinterpret_cast<char*>(asyncReply_.data() + asyncReplySize_),
                static_cast<int>(target), 0);
            if (received == SOCKET_ERROR) {
                const int error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK || error == WSAEINTR)
                    return Socks5UdpAssociationAsyncResult::Pending;
                return fail(error);
            }
            if (received == 0) return fail(WSAECONNRESET);
            asyncReplySize_ += static_cast<std::size_t>(received);
            if (asyncReplySize_ < asyncReplyExpected_)
                return Socks5UdpAssociationAsyncResult::Pending;
            if (asyncReplySize_ == 4) {
                switch (asyncReply_[3]) {
                case 1: asyncReplyExpected_ = 10; break;
                case 4: asyncReplyExpected_ = 22; break;
                case 3: asyncReplyExpected_ = 5; break;
                default: return fail(WSAEPROTONOSUPPORT);
                }
            } else if (asyncReplySize_ == 5 && asyncReply_[3] == 3) {
                if (asyncReply_[4] == 0) return fail(WSAEPROTONOSUPPORT);
                asyncReplyExpected_ = 7 + asyncReply_[4];
            }
            if (asyncReplySize_ < asyncReplyExpected_)
                return Socks5UdpAssociationAsyncResult::Pending;

            Socks5UdpAssociateReplyView reply{};
            if (ParseSocks5UdpAssociateReply(asyncReply_.data(), asyncReplySize_, reply) !=
                Socks5UdpAssociateReplyResult::Valid)
                return fail(reply.replyCode == 0 ? WSAEPROTONOSUPPORT : WSAECONNREFUSED);
            if (!BuildRelayEndpoint(reinterpret_cast<const sockaddr*>(&socksAddress_),
                    reply, relayAddress_, relayAddressLength_))
                return fail(WSAEAFNOSUPPORT);
            asyncState_ = Socks5UdpAssociationAsyncState::Ready;
            return Socks5UdpAssociationAsyncResult::Ready;
        }
        return Socks5UdpAssociationAsyncResult::Pending;
    }
    return Socks5UdpAssociationAsyncResult::Pending;
}

Socks5UdpAssociationAsyncState Socks5UdpAssociationClient::AsyncState() const noexcept {
    return asyncState_;
}

bool Socks5UdpAssociationClient::WantsRead() const noexcept {
    return asyncState_ == Socks5UdpAssociationAsyncState::Connecting ||
        asyncState_ == Socks5UdpAssociationAsyncState::ReceivingMethod ||
        asyncState_ == Socks5UdpAssociationAsyncState::ReceivingAssociateReply;
}

bool Socks5UdpAssociationClient::WantsWrite() const noexcept {
    return asyncState_ == Socks5UdpAssociationAsyncState::Connecting ||
        asyncState_ == Socks5UdpAssociationAsyncState::SendingGreeting ||
        asyncState_ == Socks5UdpAssociationAsyncState::SendingAssociateRequest;
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
    socksAddress_ = sockaddr_storage{};
    socksAddressLength_ = 0;
    asyncDeadline_ = 0;
    asyncRequestLength_ = asyncSendOffset_ = 0;
    asyncReplySize_ = 0;
    asyncReplyExpected_ = 4;
    asyncState_ = Socks5UdpAssociationAsyncState::Idle;
    asyncError_ = 0;
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
