#pragma once
#include "WfpSocks5UdpAssociationClient.h"
#include "WfpSocks5UdpRelayTransport.h"
#include "WfpSocks5UdpRedirectRecord.h"
#include <vector>

namespace furious::wfp::broker {

enum class WfpSocks5UdpFlowRelayResult {
    Ready, Pending, AlreadyOpen, InvalidArgument, SocketOpenFailed, AssociationOpenFailed,
    NotReady, ControlClosed, SendWouldBlock, SendFailed, ReceivePending, ReceiveDropped, ReceiveFailed,
    UnexpectedDestination, ForwardFailed
};

// One redirected UDP flow bridged to one local SOCKS5 UDP ASSOCIATE.
class WfpSocks5UdpFlowRelay final {
public:
    WfpSocks5UdpFlowRelay() noexcept = default;
    ~WfpSocks5UdpFlowRelay();
    WfpSocks5UdpFlowRelay(const WfpSocks5UdpFlowRelay&) = delete;
    WfpSocks5UdpFlowRelay& operator=(const WfpSocks5UdpFlowRelay&) = delete;

    WfpSocks5UdpFlowRelayResult Open(
        const sockaddr* socksAddress, int socksAddressLength,
        const sockaddr* originalClient, int originalClientLength,
        const FURIOUS_WFP_REDIRECT_CONTEXT& context,
        const std::vector<std::uint8_t>& redirectRecord,
        DWORD timeoutMilliseconds = 5000, int* errorCode = nullptr,
        ActiveSocketRegister registerSocket = nullptr,
        ActiveSocketUnregister unregisterSocket = nullptr,
        void* callbackContext = nullptr) noexcept;

    // Async variant used by the UDP broker event loop. It never waits for
    // SOCKS5 connect/handshake completion.
    WfpSocks5UdpFlowRelayResult BeginOpen(
        const sockaddr* socksAddress, int socksAddressLength,
        const sockaddr* originalClient, int originalClientLength,
        const FURIOUS_WFP_REDIRECT_CONTEXT& context,
        const std::vector<std::uint8_t>& redirectRecord,
        DWORD timeoutMilliseconds = 5000, int* errorCode = nullptr,
        ActiveSocketRegister registerSocket = nullptr,
        ActiveSocketUnregister unregisterSocket = nullptr,
        void* callbackContext = nullptr) noexcept;
    WfpSocks5UdpFlowRelayResult AdvanceOpen(
        bool readable, bool writable, int* errorCode = nullptr) noexcept;
    bool IsOpening() const noexcept;
    bool WantsRead() const noexcept;
    bool WantsWrite() const noexcept;

    void Close() noexcept;
    bool IsOpen() const noexcept;
    WfpSocks5UdpFlowRelayResult SendClientPayload(
        const std::uint8_t* payload, std::size_t payloadLength,
        int* errorCode = nullptr) noexcept;
    WfpSocks5UdpFlowRelayResult ReceiveUpstreamResponse(
        std::uint8_t* buffer, std::size_t capacity,
        Socks5UdpDatagramView& response, std::size_t& receivedLength,
        int* errorCode = nullptr) noexcept;
    WfpSocks5UdpFlowRelayResult ForwardUpstreamResponse(
        SOCKET redirectedIngressSocket, LPFN_WSASENDMSG sendMessage,
        const Socks5UdpDatagramView& response, DWORD* bytesSent = nullptr) noexcept;

    SOCKET UdpSocket() const noexcept;
    SOCKET ControlSocket() const noexcept;
    bool IsControlAlive() const noexcept;
    const sockaddr* OriginalClient() const noexcept;
    int OriginalClientLength() const noexcept;

private:
    bool MatchesOriginalDestination(const Socks5UdpDatagramView& response) const noexcept;
    Socks5UdpSocket udpSocket_;
    Socks5UdpAssociationClient association_;
    sockaddr_storage originalClient_{};
    int originalClientLength_ = 0;
    FURIOUS_WFP_REDIRECT_CONTEXT context_{};
    std::vector<std::uint8_t> redirectRecord_;
    std::vector<std::uint8_t> redirectContextBytes_;
};

} // namespace furious::wfp::broker
