#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "../include/WfpRedirectProtocol.h"
#include <cstdint>
#include <vector>

namespace furious::wfp::broker {

struct RedirectedTcpConnection final {
    std::vector<std::uint8_t> redirectRecords;
    FURIOUS_WFP_REDIRECT_CONTEXT context{};
    sockaddr_storage originalDestination{};
    int originalDestinationLength = 0;
};

int QueryRedirectedTcpConnection(
    SOCKET acceptedSocket,
    RedirectedTcpConnection& output) noexcept;

int ApplyRedirectRecords(
    SOCKET outboundSocket,
    const std::vector<std::uint8_t>& redirectRecords) noexcept;

bool BuildSocks5ConnectRequest(
    const FURIOUS_WFP_REDIRECT_CONTEXT& context,
    std::vector<std::uint8_t>& output) noexcept;

SOCKET OpenSocks5Tunnel(
    const sockaddr* socksAddress,
    int socksAddressLength,
    const RedirectedTcpConnection& redirected,
    int* errorCode) noexcept;

int RelayBidirectional(
    SOCKET clientSocket,
    SOCKET upstreamSocket,
    DWORD idleTimeoutMilliseconds = 300000) noexcept;

} // namespace furious::wfp::broker
