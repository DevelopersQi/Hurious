#pragma once

#include "WfpSocks5UdpControl.h"
#include "WfpSocks5UdpSocket.h"
#include "WfpTcpRedirect.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace furious::wfp::broker {

enum class Socks5UdpAssociationClientOpenResult {
    Opened,
    AlreadyOpen,
    InvalidArgument,
    SocketCreationFailed,
    RegistrationFailed,
    ConnectFailed,
    SocketOptionFailed,
    MethodRejected,
    RequestFailed,
    ReplyRejected,
    UnsupportedRelayEndpoint,
    NonblockingFailed
};

// Owns the TCP control connection for one upstream SOCKS5 UDP ASSOCIATE.
// The UDP data socket remains caller-owned and must outlive this object.
enum class Socks5UdpAssociationAsyncState {
    Idle, Connecting, SendingGreeting, ReceivingMethod,
    SendingAssociateRequest, ReceivingAssociateReply, Ready, Failed
};

enum class Socks5UdpAssociationAsyncResult {
    Pending, Ready, Failed, InvalidArgument, AlreadyStarted
};

class Socks5UdpAssociationClient final {
public:
    Socks5UdpAssociationClient() noexcept = default;
    ~Socks5UdpAssociationClient();

    Socks5UdpAssociationClient(const Socks5UdpAssociationClient&) = delete;
    Socks5UdpAssociationClient& operator=(const Socks5UdpAssociationClient&) = delete;

    Socks5UdpAssociationClientOpenResult Open(
        const sockaddr* socksAddress,
        int socksAddressLength,
        const Socks5UdpSocket& localUdpSocket,
        DWORD timeoutMilliseconds = 5000,
        int* errorCode = nullptr,
        ActiveSocketRegister registerSocket = nullptr,
        ActiveSocketUnregister unregisterSocket = nullptr,
        void* callbackContext = nullptr) noexcept;

    // Nonblocking API for a single-threaded broker event loop. BeginOpen never
    // waits for connect or SOCKS5 I/O; call Advance when the indicated socket
    // readiness is reported by the event loop.
    Socks5UdpAssociationAsyncResult BeginOpen(
        const sockaddr* socksAddress, int socksAddressLength,
        const Socks5UdpSocket& localUdpSocket,
        DWORD timeoutMilliseconds = 5000, int* errorCode = nullptr,
        ActiveSocketRegister registerSocket = nullptr,
        ActiveSocketUnregister unregisterSocket = nullptr,
        void* callbackContext = nullptr) noexcept;
    Socks5UdpAssociationAsyncResult Advance(
        bool readable, bool writable, int* errorCode = nullptr) noexcept;
    Socks5UdpAssociationAsyncState AsyncState() const noexcept;
    bool WantsRead() const noexcept;
    bool WantsWrite() const noexcept;

    void Close() noexcept;
    bool IsOpen() const noexcept;
    bool IsControlAlive() const noexcept;
    SOCKET ControlSocket() const noexcept;
    const sockaddr* RelayAddress() const noexcept;
    int RelayAddressLength() const noexcept;

private:
    SOCKET controlSocket_ = INVALID_SOCKET;
    sockaddr_storage relayAddress_{};
    int relayAddressLength_ = 0;
    ActiveSocketUnregister unregisterSocket_ = nullptr;
    void* callbackContext_ = nullptr;
    bool registered_ = false;

    Socks5UdpAssociationAsyncState asyncState_ = Socks5UdpAssociationAsyncState::Idle;
    sockaddr_storage socksAddress_{};
    int socksAddressLength_ = 0;
    ULONGLONG asyncDeadline_ = 0;
    std::array<std::uint8_t, 22> asyncRequest_{};
    std::size_t asyncRequestLength_ = 0;
    std::size_t asyncSendOffset_ = 0;
    std::array<std::uint8_t, 2> asyncMethodReply_{};
    std::size_t asyncMethodReplySize_ = 0;
    std::array<std::uint8_t, 262> asyncReply_{};
    std::size_t asyncReplySize_ = 0;
    std::size_t asyncReplyExpected_ = 4;
    int asyncError_ = 0;
};

} // namespace furious::wfp::broker
