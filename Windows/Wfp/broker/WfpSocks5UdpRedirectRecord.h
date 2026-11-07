#pragma once

#include <winsock2.h>
#include <mswsock.h>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace furious::wfp::broker {

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
