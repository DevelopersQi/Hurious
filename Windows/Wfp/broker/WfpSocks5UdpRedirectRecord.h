#pragma once

#include <winsock2.h>
#include <mswsock.h>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace furious::wfp::broker {

enum class WfpUdpReceiveResult {
    Received,
    WouldBlock,
    Truncated,
    InvalidSource,
    InvalidRedirectMetadata,
    InvalidArguments,
    SocketError
};

struct WfpUdpReceivedMessage final {
    sockaddr_storage sourceAddress{};
    int sourceAddressLength = 0;
    std::size_t payloadLength = 0;
    DWORD flags = 0;
    std::vector<std::uint8_t> redirectRecord;
    std::vector<std::uint8_t> redirectContext;
};

enum class WfpUdpRedirectRecordResult {
    Present,
    NotPresent,
    InvalidMessage,
    DuplicateRecord,
    RecordTooLarge,
    AllocationFailure
};

constexpr std::size_t kMaximumWfpUdpRedirectRecordSize = 64u * 1024u;

int ResolveWsaRecvMsg(SOCKET socket, LPFN_WSARECVMSG* function) noexcept;
int ResolveWsaSendMsg(SOCKET socket, LPFN_WSASENDMSG* function) noexcept;

// Redirect records and the callout-owned context are ancillary data on the
// flow-creating datagram. Each output is cleared for NotPresent and failures.
WfpUdpRedirectRecordResult ExtractWfpUdpRedirectRecord(
    const WSAMSG& message,
    std::vector<std::uint8_t>& output) noexcept;
WfpUdpRedirectRecordResult ExtractWfpUdpRedirectContext(
    const WSAMSG& message,
    std::vector<std::uint8_t>& output) noexcept;

WfpUdpReceiveResult ReceiveWfpUdpMessage(
    SOCKET socket,
    LPFN_WSARECVMSG receiveMessage,
    std::uint8_t* payloadBuffer,
    std::size_t payloadCapacity,
    char* controlBuffer,
    std::size_t controlCapacity,
    WfpUdpReceivedMessage& output,
    int* errorCode = nullptr) noexcept;

// Sends one UDP datagram, optionally attaching the first-packet redirect
// record as an ancillary control message. Empty record means a later packet.
int SendWfpUdpMessage(
    SOCKET socket,
    LPFN_WSASENDMSG sendMessage,
    const sockaddr* destination,
    int destinationLength,
    const std::uint8_t* payload,
    std::size_t payloadLength,
    const std::vector<std::uint8_t>& redirectRecord,
    const std::vector<std::uint8_t>& redirectContext,
    DWORD* bytesSent = nullptr) noexcept;

} // namespace furious::wfp::broker
