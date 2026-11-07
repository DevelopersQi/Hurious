#pragma once

#include "WfpSocks5UdpAssociation.h"

#include <winsock2.h>
#include <cstdint>

namespace furious::wfp::broker {

enum class Socks5UdpSocketOpenResult {
    Opened,
    AlreadyOpen,
    UnsupportedAddressFamily,
    SocketCreationFailed,
    SocketOptionFailed,
    BindFailed,
    QueryBoundPortFailed,
    NonblockingFailed
};

constexpr int kSocks5UdpSocketBufferBytes = 64 * 1024;

// Owns one wildcard-bound, ephemeral UDP socket. Winsock must already be
// initialized by the hosting service; this class never calls WSAStartup/WSACleanup.
class Socks5UdpSocket final {
public:
    Socks5UdpSocket() noexcept = default;
    ~Socks5UdpSocket();

    Socks5UdpSocket(const Socks5UdpSocket&) = delete;
    Socks5UdpSocket& operator=(const Socks5UdpSocket&) = delete;
    Socks5UdpSocket(Socks5UdpSocket&&) = delete;
    Socks5UdpSocket& operator=(Socks5UdpSocket&&) = delete;

    Socks5UdpSocketOpenResult Open(
        Socks5UdpEndpointFamily family,
        int* errorCode = nullptr) noexcept;
    void Close() noexcept;

    bool IsOpen() const noexcept;
    SOCKET NativeHandle() const noexcept;
    Socks5UdpEndpointFamily Family() const noexcept;
    std::uint16_t LocalPort() const noexcept;

private:
    SOCKET socket_ = INVALID_SOCKET;
    Socks5UdpEndpointFamily family_ = Socks5UdpEndpointFamily::Ipv4;
    std::uint16_t localPort_ = 0;
};

} // namespace furious::wfp::broker
