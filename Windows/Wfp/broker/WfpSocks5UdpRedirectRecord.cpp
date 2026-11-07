#include "WfpSocks5UdpRedirectRecord.h"

#include <mstcpip.h>
#include <ws2tcpip.h>

namespace furious::wfp::broker {
namespace {

int ResolveExtension(
    SOCKET socket,
    const GUID& extensionId,
    void* function,
    DWORD functionSize) noexcept {
    if (socket == INVALID_SOCKET) return WSAENOTSOCK;
    if (function == nullptr || functionSize == 0) return WSAEINVAL;
    DWORD bytesReturned = 0;
    if (WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
            const_cast<GUID*>(&extensionId), sizeof(extensionId),
            function, functionSize, &bytesReturned, nullptr, nullptr) == SOCKET_ERROR) {
        return WSAGetLastError();
    }
    return bytesReturned == functionSize ? 0 : WSAEPROTONOSUPPORT;
}

} // namespace

int ResolveWsaRecvMsg(SOCKET socket, LPFN_WSARECVMSG* function) noexcept {
    if (function == nullptr) return WSAEINVAL;
    *function = nullptr;
    return ResolveExtension(socket, WSAID_WSARECVMSG, function, sizeof(*function));
}

int ResolveWsaSendMsg(SOCKET socket, LPFN_WSASENDMSG* function) noexcept {
    if (function == nullptr) return WSAEINVAL;
    *function = nullptr;
    return ResolveExtension(socket, WSAID_WSASENDMSG, function, sizeof(*function));
}

WfpUdpRedirectRecordResult ExtractWfpUdpRedirectRecord(
    const WSAMSG& message,
    std::vector<std::uint8_t>& output) noexcept {
    output.clear();
    if (message.Control.len == 0) {
        return WfpUdpRedirectRecordResult::NotPresent;
    }
    if (message.Control.buf == nullptr ||
        message.Control.len > WSA_CMSG_SPACE(kMaximumWfpUdpRedirectRecordSize)) {
        return WfpUdpRedirectRecordResult::InvalidMessage;
    }

    bool found = false;
    WSAMSG* mutableMessage = const_cast<WSAMSG*>(&message);
    for (WSACMSGHDR* control = WSA_CMSG_FIRSTHDR(mutableMessage);
         control != nullptr;
         control = WSA_CMSG_NXTHDR(mutableMessage, control)) {
        const std::size_t headerLength = WSA_CMSG_LEN(0);
        if (control->cmsg_len < headerLength ||
            control->cmsg_len > message.Control.len) {
            output.clear();
            return WfpUdpRedirectRecordResult::InvalidMessage;
        }
        if (control->cmsg_type != IP_CONNECTION_REDIRECT_RECORD ||
            (control->cmsg_level != IPPROTO_IP &&
             control->cmsg_level != IPPROTO_IPV6)) {
            continue;
        }
        if (found) {
            output.clear();
            return WfpUdpRedirectRecordResult::DuplicateRecord;
        }
        const std::size_t recordLength = control->cmsg_len - headerLength;
        if (recordLength == 0) {
            return WfpUdpRedirectRecordResult::InvalidMessage;
        }
        if (recordLength > kMaximumWfpUdpRedirectRecordSize) {
            return WfpUdpRedirectRecordResult::RecordTooLarge;
        }
        const auto* record = reinterpret_cast<const std::uint8_t*>(
            WSA_CMSG_DATA(control));
        try {
            output.assign(record, record + recordLength);
        } catch (...) {
            output.clear();
            return WfpUdpRedirectRecordResult::AllocationFailure;
        }
        found = true;
    }
    return found ? WfpUdpRedirectRecordResult::Present
                 : WfpUdpRedirectRecordResult::NotPresent;
}

int SendWfpUdpMessage(
    SOCKET socket,
    LPFN_WSASENDMSG sendMessage,
    const sockaddr* destination,
    int destinationLength,
    const std::uint8_t* payload,
    std::size_t payloadLength,
    const std::vector<std::uint8_t>& redirectRecord,
    DWORD* bytesSent) noexcept {
    if (bytesSent != nullptr) *bytesSent = 0;
    if (socket == INVALID_SOCKET) return WSAENOTSOCK;
    if (sendMessage == nullptr || destination == nullptr ||
        (payload == nullptr && payloadLength != 0) ||
        payloadLength > 65507 ||
        redirectRecord.size() > kMaximumWfpUdpRedirectRecordSize) {
        return WSAEINVAL;
    }
    if ((destination->sa_family == AF_INET &&
            destinationLength < static_cast<int>(sizeof(sockaddr_in))) ||
        (destination->sa_family == AF_INET6 &&
            destinationLength < static_cast<int>(sizeof(sockaddr_in6))) ||
        (destination->sa_family != AF_INET && destination->sa_family != AF_INET6)) {
        return WSAEAFNOSUPPORT;
    }

    WSABUF buffer{};
    buffer.buf = const_cast<char*>(reinterpret_cast<const char*>(payload));
    buffer.len = static_cast<ULONG>(payloadLength);
    WSAMSG message{};
    message.name = const_cast<sockaddr*>(destination);
    message.namelen = destinationLength;
    message.lpBuffers = &buffer;
    message.dwBufferCount = 1;

    std::vector<char> controlBuffer;
    if (!redirectRecord.empty()) {
        try {
            controlBuffer.resize(WSA_CMSG_SPACE(redirectRecord.size()));
        } catch (...) {
            return WSA_NOT_ENOUGH_MEMORY;
        }
        message.Control.buf = controlBuffer.data();
        message.Control.len = static_cast<ULONG>(controlBuffer.size());
        WSACMSGHDR* control = WSA_CMSG_FIRSTHDR(&message);
        if (control == nullptr) return WSAEINVAL;
        control->cmsg_level = destination->sa_family == AF_INET
            ? IPPROTO_IP : IPPROTO_IPV6;
        control->cmsg_type = IP_CONNECTION_REDIRECT_RECORD;
        control->cmsg_len = WSA_CMSG_LEN(redirectRecord.size());
        std::memcpy(WSA_CMSG_DATA(control), redirectRecord.data(),
            redirectRecord.size());
    }

    DWORD localBytesSent = 0;
    if (sendMessage(socket, &message, 0,
            bytesSent != nullptr ? bytesSent : &localBytesSent,
            nullptr, nullptr) == SOCKET_ERROR) {
        return WSAGetLastError();
    }
    return 0;
}

} // namespace furious::wfp::broker
