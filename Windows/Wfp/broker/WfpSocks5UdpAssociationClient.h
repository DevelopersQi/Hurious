#pragma once

#include "WfpSocks5UdpControl.h"
#include "WfpSocks5UdpSocket.h"
#include "WfpTcpRedirect.h"

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
};

} // namespace furious::wfp::broker
