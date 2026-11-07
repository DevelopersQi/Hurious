#include "WfpSocks5UdpRelayTransport.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <vector>

namespace furious::wfp::broker {
namespace {

bool IsValidSocketAddress(const sockaddr* address, int length) noexcept {
    if (address == nullptr) return false;
    if (address->sa_family == AF_INET) return length >= static_cast<int>(sizeof(sockaddr_in));
    if (address->sa_family == AF_INET6) return length >= static_cast<int>(sizeof(sockaddr_in6));
    return false;
}

bool SameEndpoint(
    const sockaddr* expected, int expectedLength,
    const sockaddr* actual, int actualLength) noexcept {
    if (!IsValidSocketAddress(expected, expectedLength) ||
        !IsValidSocketAddress(actual, actualLength) ||
        expected->sa_family != actual->sa_family) {
        return false;
    }
    if (expected->sa_family == AF_INET) {
        const auto* a = reinterpret_cast<const sockaddr_in*>(expected);
        const auto* b = reinterpret_cast<const sockaddr_in*>(actual);
        return a->sin_port == b->sin_port &&
            a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    const auto* a = reinterpret_cast<const sockaddr_in6*>(expected);
    const auto* b = reinterpret_cast<const sockaddr_in6*>(actual);
    return a->sin6_port == b->sin6_port &&
        a->sin6_scope_id == b->sin6_scope_id &&
        std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(IN6_ADDR)) == 0;
}

} // namespace

Socks5UdpRelayIoResult SendSocks5UdpToRelay(
    SOCKET socket,
    const sockaddr* relayAddress,
    int relayAddressLength,
    Socks5UdpAddressType targetType,
    const std::uint8_t* targetAddress,
    std::size_t targetAddressLength,
    std::uint16_t targetPort,
    const std::uint8_t* payload,
    std::size_t payloadLength,
    std::size_t maximumDatagramLength,
    int* errorCode) noexcept {
    if (errorCode != nullptr) *errorCode = 0;
    if (socket == INVALID_SOCKET ||
        !IsValidSocketAddress(relayAddress, relayAddressLength) ||
        targetPort == 0 ||
        (targetAddress == nullptr && targetAddressLength != 0) ||
        (payload == nullptr && payloadLength != 0) ||
        maximumDatagramLength == 0 ||
        maximumDatagramLength > kMaximumSocks5UdpDatagramSize) {
        if (errorCode != nullptr) *errorCode = WSAEINVAL;
        return Socks5UdpRelayIoResult::InvalidArgument;
    }
    try {
        std::vector<std::uint8_t> datagram;
        const auto built = BuildSocks5UdpDatagram(
            targetType, targetAddress, targetAddressLength, targetPort,
            payload, payloadLength, datagram, maximumDatagramLength);
        if (built != Socks5UdpBuildResult::Valid) {
            if (errorCode != nullptr) {
                *errorCode = built == Socks5UdpBuildResult::DatagramTooLarge
                    ? WSAEMSGSIZE : WSAEINVAL;
            }
            return Socks5UdpRelayIoResult::InvalidArgument;
        }
        const int sent = sendto(socket,
            reinterpret_cast<const char*>(datagram.data()),
            static_cast<int>(datagram.size()), 0,
            relayAddress, relayAddressLength);
        if (sent == SOCKET_ERROR) {
            if (errorCode != nullptr) *errorCode = WSAGetLastError();
            return Socks5UdpRelayIoResult::SocketError;
        }
        if (static_cast<std::size_t>(sent) != datagram.size()) {
            if (errorCode != nullptr) *errorCode = WSAEMSGSIZE;
            return Socks5UdpRelayIoResult::ShortSend;
        }
        return Socks5UdpRelayIoResult::Sent;
    } catch (...) {
        if (errorCode != nullptr) *errorCode = WSA_NOT_ENOUGH_MEMORY;
        return Socks5UdpRelayIoResult::SocketError;
    }
}

Socks5UdpRelayIoResult ReceiveSocks5UdpFromRelay(
    SOCKET socket,
    const sockaddr* expectedRelayAddress,
    int expectedRelayAddressLength,
    std::uint8_t* buffer,
    std::size_t bufferCapacity,
    Socks5UdpDatagramView& output,
    std::size_t& receivedLength,
    int* errorCode) noexcept {
    output = Socks5UdpDatagramView{};
    receivedLength = 0;
    if (errorCode != nullptr) *errorCode = 0;
    if (socket == INVALID_SOCKET ||
        !IsValidSocketAddress(expectedRelayAddress, expectedRelayAddressLength) ||
        buffer == nullptr || bufferCapacity == 0 ||
        bufferCapacity > static_cast<std::size_t>((std::numeric_limits<int>::max)())) {
        if (errorCode != nullptr) *errorCode = WSAEINVAL;
        return Socks5UdpRelayIoResult::InvalidArgument;
    }

    sockaddr_storage source{};
    int sourceLength = sizeof(source);
    const int received = recvfrom(socket, reinterpret_cast<char*>(buffer),
        static_cast<int>(bufferCapacity), 0,
        reinterpret_cast<sockaddr*>(&source), &sourceLength);
    if (received == SOCKET_ERROR) {
        const int error = WSAGetLastError();
        if (errorCode != nullptr) *errorCode = error;
        return error == WSAEWOULDBLOCK
            ? Socks5UdpRelayIoResult::WouldBlock
            : Socks5UdpRelayIoResult::SocketError;
    }

    if (!SameEndpoint(expectedRelayAddress, expectedRelayAddressLength,
            reinterpret_cast<const sockaddr*>(&source), sourceLength)) {
        if (errorCode != nullptr) *errorCode = WSAEACCES;
        return Socks5UdpRelayIoResult::UnexpectedRelay;
    }

    receivedLength = static_cast<std::size_t>(received);
    if (receivedLength == bufferCapacity) {
        // recvfrom cannot distinguish an exactly full datagram from a truncated one.
        // Treat a full buffer as ambiguous and fail closed.
        if (errorCode != nullptr) *errorCode = WSAEMSGSIZE;
        receivedLength = 0;
        return Socks5UdpRelayIoResult::BufferTooSmall;
    }
    if (ParseSocks5UdpDatagram(buffer, receivedLength, output) !=
        Socks5UdpParseResult::Valid) {
        output = Socks5UdpDatagramView{};
        receivedLength = 0;
        if (errorCode != nullptr) *errorCode = WSAEPROTONOSUPPORT;
        return Socks5UdpRelayIoResult::InvalidDatagram;
    }
    return Socks5UdpRelayIoResult::Received;
}

} // namespace furious::wfp::broker
