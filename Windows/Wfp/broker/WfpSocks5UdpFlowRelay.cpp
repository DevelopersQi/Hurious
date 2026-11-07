#include "WfpSocks5UdpFlowRelay.h"
#include <cstring>
#include <ws2tcpip.h>

namespace furious::wfp::broker {
namespace {
bool ValidEndpoint(const sockaddr* address, int length) noexcept {
    if (!address) return false;
    if (address->sa_family == AF_INET) {
        if (length != static_cast<int>(sizeof(sockaddr_in))) return false;
        const auto* value = reinterpret_cast<const sockaddr_in*>(address);
        const auto first = ntohl(value->sin_addr.s_addr) >> 24;
        return value->sin_port != 0 && first != 0 && first < 224;
    }
    if (address->sa_family == AF_INET6) {
        if (length != static_cast<int>(sizeof(sockaddr_in6))) return false;
        const auto* value = reinterpret_cast<const sockaddr_in6*>(address);
        return value->sin6_port != 0 &&
            !IN6_IS_ADDR_UNSPECIFIED(&value->sin6_addr) &&
            !IN6_IS_ADDR_MULTICAST(&value->sin6_addr);
    }
    return false;
}
}
WfpSocks5UdpFlowRelay::~WfpSocks5UdpFlowRelay() { Close(); }

WfpSocks5UdpFlowRelayResult WfpSocks5UdpFlowRelay::Open(
    const sockaddr* socksAddress, int socksAddressLength,
    const sockaddr* originalClient, int originalClientLength,
    const FURIOUS_WFP_REDIRECT_CONTEXT& context,
    const std::vector<std::uint8_t>& redirectRecord,
    DWORD timeoutMilliseconds, int* errorCode) noexcept {
    if (errorCode) *errorCode = 0;
    if (IsOpen()) return WfpSocks5UdpFlowRelayResult::AlreadyOpen;
    bool validDestination = false;
    if (context.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4) {
        validDestination = context.OriginalAddress[0] != 0 &&
            context.OriginalAddress[0] < 224;
    } else if (context.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V6) {
        bool unspecified = true;
        for (const auto byte : context.OriginalAddress) {
            if (byte != 0) { unspecified = false; break; }
        }
        validDestination = !unspecified && context.OriginalAddress[0] != 0xFF;
    }
    if (!ValidEndpoint(originalClient, originalClientLength) ||
        redirectRecord.empty() ||
        redirectRecord.size() > kMaximumWfpUdpRedirectRecordSize ||
        !furious::wfp::redirect::IsValidRedirectContext(context) ||
        context.Protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_UDP ||
        !validDestination ||
        (originalClient->sa_family == AF_INET &&
            context.AddressFamily != FURIOUS_WFP_REDIRECT_FAMILY_V4) ||
        (originalClient->sa_family == AF_INET6 &&
            context.AddressFamily != FURIOUS_WFP_REDIRECT_FAMILY_V6)) {
        if (errorCode) *errorCode = WSAEINVAL;
        return WfpSocks5UdpFlowRelayResult::InvalidArgument;
    }
    const auto family = originalClient->sa_family == AF_INET
        ? Socks5UdpEndpointFamily::Ipv4 : Socks5UdpEndpointFamily::Ipv6;
    int error = 0;
    if (udpSocket_.Open(family, &error) != Socks5UdpSocketOpenResult::Opened) {
        if (errorCode) *errorCode = error;
        return WfpSocks5UdpFlowRelayResult::SocketOpenFailed;
    }
    const auto opened = association_.Open(socksAddress, socksAddressLength,
        udpSocket_, timeoutMilliseconds, &error);
    if (opened != Socks5UdpAssociationClientOpenResult::Opened) {
        if (errorCode) *errorCode = error;
        Close();
        return WfpSocks5UdpFlowRelayResult::AssociationOpenFailed;
    }
    std::memcpy(&originalClient_, originalClient,
        static_cast<std::size_t>(originalClientLength));
    originalClientLength_ = originalClientLength;
    context_ = context;
    try {
        redirectRecord_ = redirectRecord;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&context_);
        redirectContextBytes_.assign(bytes, bytes + sizeof(context_));
    } catch (...) {
        if (errorCode) *errorCode = WSA_NOT_ENOUGH_MEMORY;
        Close();
        return WfpSocks5UdpFlowRelayResult::AssociationOpenFailed;
    }
    return WfpSocks5UdpFlowRelayResult::Ready;
}

void WfpSocks5UdpFlowRelay::Close() noexcept {
    association_.Close();
    udpSocket_.Close();
    originalClient_ = sockaddr_storage{};
    originalClientLength_ = 0;
    context_ = FURIOUS_WFP_REDIRECT_CONTEXT{};
    redirectRecord_.clear();
    redirectContextBytes_.clear();
}
bool WfpSocks5UdpFlowRelay::IsOpen() const noexcept {
    return udpSocket_.IsOpen() && association_.IsOpen() &&
        originalClientLength_ != 0;
}

bool WfpSocks5UdpFlowRelay::MatchesOriginalDestination(
    const Socks5UdpDatagramView& response) const noexcept {
    const std::uint16_t port = ntohs(context_.OriginalPortNetworkOrder);
    if (response.address == nullptr || response.port != port) return false;
    if (context_.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4) {
        return response.addressType == Socks5UdpAddressType::Ipv4 &&
            response.addressLength == 4 &&
            std::memcmp(response.address, context_.OriginalAddress, 4) == 0;
    }
    return response.addressType == Socks5UdpAddressType::Ipv6 &&
        response.addressLength == 16 &&
        std::memcmp(response.address, context_.OriginalAddress, 16) == 0;
}

WfpSocks5UdpFlowRelayResult WfpSocks5UdpFlowRelay::SendClientPayload(
    const std::uint8_t* payload, std::size_t payloadLength, int* errorCode) noexcept {
    if (errorCode) *errorCode = 0;
    if (!IsOpen()) return WfpSocks5UdpFlowRelayResult::NotReady;
    if (!association_.IsControlAlive()) {
        Close();
        return WfpSocks5UdpFlowRelayResult::ControlClosed;
    }
    const bool v4 = context_.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4;
    const auto type = v4 ? Socks5UdpAddressType::Ipv4 : Socks5UdpAddressType::Ipv6;
    const std::size_t addressLength = v4 ? 4 : 16;
    const auto result = SendSocks5UdpToRelay(udpSocket_.NativeHandle(),
        association_.RelayAddress(), association_.RelayAddressLength(),
        type, context_.OriginalAddress, addressLength,
        ntohs(context_.OriginalPortNetworkOrder), payload, payloadLength,
        kMaximumSocks5UdpDatagramSize, errorCode);
    return result == Socks5UdpRelayIoResult::Sent
        ? WfpSocks5UdpFlowRelayResult::Ready
        : WfpSocks5UdpFlowRelayResult::SendFailed;
}

WfpSocks5UdpFlowRelayResult WfpSocks5UdpFlowRelay::ReceiveUpstreamResponse(
    std::uint8_t* buffer, std::size_t capacity, Socks5UdpDatagramView& response,
    std::size_t& receivedLength, int* errorCode) noexcept {
    response = Socks5UdpDatagramView{};
    receivedLength = 0;
    if (!IsOpen()) return WfpSocks5UdpFlowRelayResult::NotReady;
    if (!association_.IsControlAlive()) {
        Close();
        return WfpSocks5UdpFlowRelayResult::ControlClosed;
    }
    Socks5UdpDatagramView parsed{};
    const auto result = ReceiveSocks5UdpFromRelay(udpSocket_.NativeHandle(),
        association_.RelayAddress(), association_.RelayAddressLength(),
        buffer, capacity, parsed, receivedLength, errorCode);
    if (result == Socks5UdpRelayIoResult::WouldBlock)
        return WfpSocks5UdpFlowRelayResult::ReceivePending;
    if (result != Socks5UdpRelayIoResult::Received)
        return WfpSocks5UdpFlowRelayResult::ReceiveFailed;
    if (!MatchesOriginalDestination(parsed)) {
        receivedLength = 0;
        return WfpSocks5UdpFlowRelayResult::UnexpectedDestination;
    }
    response = parsed;
    return WfpSocks5UdpFlowRelayResult::Ready;
}

WfpSocks5UdpFlowRelayResult WfpSocks5UdpFlowRelay::ForwardUpstreamResponse(
    SOCKET ingress, LPFN_WSASENDMSG sendMessage,
    const Socks5UdpDatagramView& response, DWORD* bytesSent) noexcept {
    if (bytesSent) *bytesSent = 0;
    if (!IsOpen() || response.payload == nullptr)
        return WfpSocks5UdpFlowRelayResult::NotReady;
    if (!association_.IsControlAlive()) {
        Close();
        return WfpSocks5UdpFlowRelayResult::ControlClosed;
    }
    if (!MatchesOriginalDestination(response))
        return WfpSocks5UdpFlowRelayResult::UnexpectedDestination;
    const int error = SendWfpUdpMessage(ingress, sendMessage,
        reinterpret_cast<const sockaddr*>(&originalClient_), originalClientLength_,
        response.payload, response.payloadLength, redirectRecord_,
        redirectContextBytes_, bytesSent);
    return error == 0 ? WfpSocks5UdpFlowRelayResult::Ready
                      : WfpSocks5UdpFlowRelayResult::ForwardFailed;
}
SOCKET WfpSocks5UdpFlowRelay::UdpSocket() const noexcept {
    return udpSocket_.NativeHandle();
}
const sockaddr* WfpSocks5UdpFlowRelay::OriginalClient() const noexcept {
    return originalClientLength_ == 0 ? nullptr :
        reinterpret_cast<const sockaddr*>(&originalClient_);
}
int WfpSocks5UdpFlowRelay::OriginalClientLength() const noexcept {
    return originalClientLength_;
}
} // namespace furious::wfp::broker
