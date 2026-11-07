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

// The redirect record is present only on the flow-creating datagram. The
// output is cleared for NotPresent and every failure result.
WfpUdpRedirectRecordResult ExtractWfpUdpRedirectRecord(
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
    DWORD* bytesSent = nullptr) noexcept;

} // namespace furious::wfp::broker
