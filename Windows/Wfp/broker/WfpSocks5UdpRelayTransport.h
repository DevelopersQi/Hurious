#pragma once

#include "WfpSocks5Udp.h"
#include <winsock2.h>
#include <cstddef>
#include <cstdint>

namespace furious::wfp::broker {

enum class Socks5UdpRelayIoResult {
    Sent,
    Received,
    WouldBlock,
    InvalidArgument,
    SocketError,
    ShortSend,
    UnexpectedRelay,
    InvalidDatagram,
    BufferTooSmall
};

// Sends one SOCKS5 UDP-encapsulated datagram to the negotiated relay endpoint.
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
    int* errorCode = nullptr) noexcept;

// Receives one datagram, accepts only the exact negotiated relay endpoint,
// and returns a non-owning parsed view into the caller-provided buffer.
Socks5UdpRelayIoResult ReceiveSocks5UdpFromRelay(
    SOCKET socket,
    const sockaddr* expectedRelayAddress,
    int expectedRelayAddressLength,
    std::uint8_t* buffer,
    std::size_t bufferCapacity,
    Socks5UdpDatagramView& output,
    std::size_t& receivedLength,
    int* errorCode = nullptr) noexcept;

} // namespace furious::wfp::broker
