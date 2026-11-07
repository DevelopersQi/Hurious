#include "WfpSocks5UdpRedirectRecord.h"

#include <cstring>
#include <climits>
#include <mstcpip.h>
#include <ws2tcpip.h>

namespace furious::wfp::broker {
namespace {

WfpUdpRedirectRecordResult ExtractControlData(
    const WSAMSG& message,
    int messageType,
    std::vector<std::uint8_t>& output) noexcept {
    output.clear();
    if (message.Control.len == 0) {
        return WfpUdpRedirectRecordResult::NotPresent;
    }
    if (message.Control.buf == nullptr ||
        message.Control.len > 2 * WSA_CMSG_SPACE(kMaximumWfpUdpRedirectRecordSize)) {
        return WfpUdpRedirectRecordResult::InvalidMessage;
    }

    bool found = false;
    int expectedLevel = 0;
    if (message.name != nullptr) {
        if (message.name->sa_family == AF_INET) {
            expectedLevel = IPPROTO_IP;
        } else if (message.name->sa_family == AF_INET6) {
            expectedLevel = IPPROTO_IPV6;
        } else {
            return WfpUdpRedirectRecordResult::InvalidMessage;
        }
    }
    WSAMSG* mutableMessage = const_cast<WSAMSG*>(&message);
    const char* controlBegin = message.Control.buf;
    const char* controlEnd = controlBegin + message.Control.len;
    for (WSACMSGHDR* control = WSA_CMSG_FIRSTHDR(mutableMessage);
         control != nullptr;
         control = WSA_CMSG_NXTHDR(mutableMessage, control)) {
        const char* controlAddress = reinterpret_cast<const char*>(control);
        if (controlAddress < controlBegin || controlAddress > controlEnd) {
            return WfpUdpRedirectRecordResult::InvalidMessage;
        }
        const std::size_t remaining =
            static_cast<std::size_t>(controlEnd - controlAddress);
        const std::size_t headerLength = WSA_CMSG_LEN(0);
        if (control->cmsg_len < headerLength ||
            control->cmsg_len > remaining) {
            output.clear();
            return WfpUdpRedirectRecordResult::InvalidMessage;
        }
        if (control->cmsg_type != messageType) {
            continue;
        }
        if ((expectedLevel != 0 && control->cmsg_level != expectedLevel) ||
            (control->cmsg_level != IPPROTO_IP &&
             control->cmsg_level != IPPROTO_IPV6)) {
            output.clear();
            return WfpUdpRedirectRecordResult::InvalidMessage;
        }
        if (found) {
            output.clear();
            return WfpUdpRedirectRecordResult::DuplicateRecord;
        }
        const std::size_t dataLength = control->cmsg_len - headerLength;
        if (dataLength == 0) {
            return WfpUdpRedirectRecordResult::InvalidMessage;
        }
        if (dataLength > kMaximumWfpUdpRedirectRecordSize) {
            return WfpUdpRedirectRecordResult::RecordTooLarge;
        }
        const auto* data = reinterpret_cast<const std::uint8_t*>(
            WSA_CMSG_DATA(control));
        try {
            output.assign(data, data + dataLength);
        } catch (...) {
            output.clear();
            return WfpUdpRedirectRecordResult::AllocationFailure;
        }
        found = true;
    }
    return found ? WfpUdpRedirectRecordResult::Present
                 : WfpUdpRedirectRecordResult::NotPresent;
}

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
    return ExtractControlData(message, IP_WFP_REDIRECT_RECORDS, output);
}

WfpUdpRedirectRecordResult ExtractWfpUdpRedirectContext(
    const WSAMSG& message,
    std::vector<std::uint8_t>& output) noexcept {
    return ExtractControlData(message, IP_WFP_REDIRECT_CONTEXT, output);
}

WfpUdpRedirectContextDecodeResult DecodeWfpUdpRedirectContext(
    const std::vector<std::uint8_t>& bytes,
    FURIOUS_WFP_REDIRECT_CONTEXT& output) noexcept {
    std::memset(&output, 0, sizeof(output));
    if (bytes.size() != sizeof(FURIOUS_WFP_REDIRECT_CONTEXT)) {
        return WfpUdpRedirectContextDecodeResult::InvalidSize;
    }
    std::memcpy(&output, bytes.data(), sizeof(output));
    if (!furious::wfp::redirect::IsValidRedirectContext(output)) {
        std::memset(&output, 0, sizeof(output));
        return WfpUdpRedirectContextDecodeResult::InvalidContext;
    }
    if (output.Protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_UDP) {
        std::memset(&output, 0, sizeof(output));
        return WfpUdpRedirectContextDecodeResult::NotUdp;
    }
    return WfpUdpRedirectContextDecodeResult::Decoded;
}

WfpUdpReceiveResult ReceiveWfpUdpMessage(
    SOCKET socket,
    LPFN_WSARECVMSG receiveMessage,
    std::uint8_t* payloadBuffer,
    std::size_t payloadCapacity,
    char* controlBuffer,
    std::size_t controlCapacity,
    WfpUdpReceivedMessage& output,
    int* errorCode) noexcept {
    output = WfpUdpReceivedMessage{};
    if (errorCode != nullptr) *errorCode = 0;
    if (socket == INVALID_SOCKET || receiveMessage == nullptr ||
        payloadBuffer == nullptr || payloadCapacity == 0 ||
        payloadCapacity > static_cast<std::size_t>(ULONG_MAX) ||
        controlBuffer == nullptr || controlCapacity < WSA_CMSG_SPACE(0) ||
        controlCapacity > static_cast<std::size_t>(ULONG_MAX)) {
        if (errorCode != nullptr) *errorCode = WSAEINVAL;
        return WfpUdpReceiveResult::InvalidArguments;
    }

    WSABUF payload{};
    payload.buf = reinterpret_cast<char*>(payloadBuffer);
    payload.len = static_cast<ULONG>(payloadCapacity);
    WSAMSG message{};
    message.name = reinterpret_cast<sockaddr*>(&output.sourceAddress);
    message.namelen = sizeof(output.sourceAddress);
    message.lpBuffers = &payload;
    message.dwBufferCount = 1;
    message.Control.buf = controlBuffer;
    message.Control.len = static_cast<ULONG>(controlCapacity);

    DWORD bytesReceived = 0;
    if (receiveMessage(socket, &message, &bytesReceived, nullptr, nullptr) ==
            SOCKET_ERROR) {
        const int error = WSAGetLastError();
        if (errorCode != nullptr) *errorCode = error;
        if (error == WSAEWOULDBLOCK) return WfpUdpReceiveResult::WouldBlock;
        if (error == WSAEMSGSIZE) return WfpUdpReceiveResult::Truncated;
        return WfpUdpReceiveResult::SocketError;
    }

    if ((message.dwFlags & MSG_PARTIAL) != 0 ||
        bytesReceived > payloadCapacity ||
        message.Control.len >= controlCapacity) {
        if (errorCode != nullptr) *errorCode = WSAEMSGSIZE;
        return WfpUdpReceiveResult::Truncated;
    }
    if ((message.name->sa_family == AF_INET &&
            message.namelen < static_cast<int>(sizeof(sockaddr_in))) ||
        (message.name->sa_family == AF_INET6 &&
            message.namelen < static_cast<int>(sizeof(sockaddr_in6))) ||
        (message.name->sa_family != AF_INET && message.name->sa_family != AF_INET6)) {
        if (errorCode != nullptr) *errorCode = WSAEAFNOSUPPORT;
        return WfpUdpReceiveResult::InvalidSource;
    }

    const auto recordResult = ExtractWfpUdpRedirectRecord(
        message, output.redirectRecord);
    const auto contextResult = ExtractWfpUdpRedirectContext(
        message, output.redirectContext);
    const auto validMetadata = [](WfpUdpRedirectRecordResult result) noexcept {
        return result == WfpUdpRedirectRecordResult::Present ||
            result == WfpUdpRedirectRecordResult::NotPresent;
    };
    if (!validMetadata(recordResult) || !validMetadata(contextResult)) {
        output = WfpUdpReceivedMessage{};
        if (errorCode != nullptr) *errorCode = WSAEINVAL;
        return WfpUdpReceiveResult::InvalidRedirectMetadata;
    }

    output.sourceAddressLength = message.namelen;
    output.payloadLength = bytesReceived;
    output.flags = message.dwFlags;
    return WfpUdpReceiveResult::Received;
}

int SendWfpUdpMessage(
    SOCKET socket,
    LPFN_WSASENDMSG sendMessage,
    const sockaddr* destination,
    int destinationLength,
    const std::uint8_t* payload,
    std::size_t payloadLength,
    const std::vector<std::uint8_t>& redirectRecord,
    const std::vector<std::uint8_t>& redirectContext,
    DWORD* bytesSent) noexcept {
    if (bytesSent != nullptr) *bytesSent = 0;
    if (socket == INVALID_SOCKET) return WSAENOTSOCK;
    if (sendMessage == nullptr || destination == nullptr ||
        (payload == nullptr && payloadLength != 0) ||
        payloadLength > 65507 ||
        redirectRecord.size() > kMaximumWfpUdpRedirectRecordSize ||
        redirectContext.size() > kMaximumWfpUdpRedirectRecordSize) {
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
    if (!redirectRecord.empty() || !redirectContext.empty()) {
        const std::size_t controlLength =
            (redirectRecord.empty() ? 0 : WSA_CMSG_SPACE(redirectRecord.size())) +
            (redirectContext.empty() ? 0 : WSA_CMSG_SPACE(redirectContext.size()));
        try {
            controlBuffer.resize(controlLength);
        } catch (...) {
            return WSA_NOT_ENOUGH_MEMORY;
        }
        message.Control.buf = controlBuffer.data();
        message.Control.len = static_cast<ULONG>(controlBuffer.size());
        WSACMSGHDR* control = WSA_CMSG_FIRSTHDR(&message);
        if (!redirectRecord.empty()) {
            if (control == nullptr) return WSAEINVAL;
            control->cmsg_level = destination->sa_family == AF_INET6
                ? IPPROTO_IPV6 : IPPROTO_IP;
            control->cmsg_type = IP_WFP_REDIRECT_RECORDS;
            control->cmsg_len = WSA_CMSG_LEN(redirectRecord.size());
            std::memcpy(WSA_CMSG_DATA(control), redirectRecord.data(),
                redirectRecord.size());
            control = WSA_CMSG_NXTHDR(&message, control);
        }
        if (!redirectContext.empty()) {
            if (control == nullptr) return WSAEINVAL;
            control->cmsg_level = destination->sa_family == AF_INET6
                ? IPPROTO_IPV6 : IPPROTO_IP;
            control->cmsg_type = IP_WFP_REDIRECT_CONTEXT;
            control->cmsg_len = WSA_CMSG_LEN(redirectContext.size());
            std::memcpy(WSA_CMSG_DATA(control), redirectContext.data(),
                redirectContext.size());
        }
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
