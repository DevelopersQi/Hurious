#include "WfpSocks5UdpControl.h"
namespace furious::wfp::broker {
Socks5UdpAssociateRequestResult ParseSocks5UdpAssociateRequest(
    const std::uint8_t* request, std::size_t length,
    Socks5UdpAssociateRequestView& output) noexcept {
    output = Socks5UdpAssociateRequestView{};
    if (request == nullptr) return Socks5UdpAssociateRequestResult::NullRequest;
    if (length < 4) return Socks5UdpAssociateRequestResult::Truncated;
    if (request[0] != 0x05) return Socks5UdpAssociateRequestResult::InvalidVersion;
    if (request[1] != 0x03) return Socks5UdpAssociateRequestResult::UnsupportedCommand;
    if (request[2] != 0x00) return Socks5UdpAssociateRequestResult::InvalidReservedField;
    const auto type = static_cast<Socks5UdpAddressType>(request[3]);
    std::size_t offset = 4, addressLength = 0;
    switch (type) {
    case Socks5UdpAddressType::Ipv4: addressLength = 4; break;
    case Socks5UdpAddressType::Ipv6: addressLength = 16; break;
    case Socks5UdpAddressType::Domain:
        if (length <= offset) return Socks5UdpAssociateRequestResult::Truncated;
        addressLength = request[offset++];
        if (addressLength == 0) return Socks5UdpAssociateRequestResult::EmptyDomain;
        break;
    default: return Socks5UdpAssociateRequestResult::UnsupportedAddressType;
    }
    if (offset > length || addressLength > length - offset ||
        length - offset - addressLength < 2)
        return Socks5UdpAssociateRequestResult::Truncated;
    const std::size_t portOffset = offset + addressLength;
    if (length != portOffset + 2) return Socks5UdpAssociateRequestResult::TrailingData;
    output.addressType = type;
    output.address = request + offset;
    output.addressLength = addressLength;
    output.port = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(request[portOffset]) << 8) |
        static_cast<std::uint16_t>(request[portOffset + 1]));
    return Socks5UdpAssociateRequestResult::Valid;
}
Socks5UdpBuildResult BuildSocks5UdpAssociateReply(
    Socks5UdpAddressType type, const std::uint8_t* address,
    std::size_t addressLength, std::uint16_t port,
    std::vector<std::uint8_t>& output) noexcept {
    output.clear();
    if (address == nullptr) return Socks5UdpBuildResult::NullAddress;
    if (port == 0) return Socks5UdpBuildResult::InvalidPort;
    switch (type) {
    case Socks5UdpAddressType::Ipv4:
        if (addressLength != 4) return Socks5UdpBuildResult::InvalidAddressLength;
        break;
    case Socks5UdpAddressType::Ipv6:
        if (addressLength != 16) return Socks5UdpBuildResult::InvalidAddressLength;
        break;
    case Socks5UdpAddressType::Domain:
        if (addressLength == 0) return Socks5UdpBuildResult::EmptyDomain;
        if (addressLength > 255) return Socks5UdpBuildResult::InvalidAddressLength;
        break;
    default:
        return Socks5UdpBuildResult::InvalidAddressType;
    }
    try {
        output.reserve(4 + (type == Socks5UdpAddressType::Domain ? 1 : 0)
            + addressLength + 2);
        output.insert(output.end(), {0x05, 0x00, 0x00,
            static_cast<std::uint8_t>(type)});
        if (type == Socks5UdpAddressType::Domain)
            output.push_back(static_cast<std::uint8_t>(addressLength));
        output.insert(output.end(), address, address + addressLength);
        output.push_back(static_cast<std::uint8_t>(port >> 8));
        output.push_back(static_cast<std::uint8_t>(port & 0xFF));
    } catch (...) {
        output.clear();
        return Socks5UdpBuildResult::AllocationFailure;
    }
    return Socks5UdpBuildResult::Valid;
}
}
