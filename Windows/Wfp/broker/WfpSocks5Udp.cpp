#include "WfpSocks5Udp.h"

namespace furious::wfp::broker {

Socks5UdpParseResult ParseSocks5UdpDatagram(
    const std::uint8_t* datagram,
    std::size_t datagramLength,
    Socks5UdpDatagramView& output) noexcept {
    output = Socks5UdpDatagramView{};
    if (datagram == nullptr) {
        return Socks5UdpParseResult::NullDatagram;
    }
    // RSV(2) + FRAG(1) + ATYP(1) + minimum IPv4 address(4) + PORT(2).
    if (datagramLength < 10) {
        return Socks5UdpParseResult::Truncated;
    }
    if (datagram[0] != 0 || datagram[1] != 0) {
        return Socks5UdpParseResult::InvalidReservedField;
    }
    if (datagram[2] != 0) {
        return Socks5UdpParseResult::FragmentationUnsupported;
    }

    const auto addressType = static_cast<Socks5UdpAddressType>(datagram[3]);
    std::size_t addressOffset = 4;
    std::size_t addressLength = 0;
    switch (addressType) {
    case Socks5UdpAddressType::Ipv4:
        addressLength = 4;
        break;
    case Socks5UdpAddressType::Domain:
        if (datagramLength <= addressOffset) {
            return Socks5UdpParseResult::Truncated;
        }
        addressLength = datagram[addressOffset++];
        if (addressLength == 0) {
            return Socks5UdpParseResult::EmptyDomain;
        }
        break;
    case Socks5UdpAddressType::Ipv6:
        addressLength = 16;
        break;
    default:
        return Socks5UdpParseResult::UnsupportedAddressType;
    }

    if (addressOffset > datagramLength ||
        addressLength > datagramLength - addressOffset) {
        return Socks5UdpParseResult::Truncated;
    }
    const std::size_t portOffset = addressOffset + addressLength;
    if (datagramLength - portOffset < 2) {
        return Socks5UdpParseResult::Truncated;
    }
    const std::uint16_t port = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(datagram[portOffset]) << 8) |
        static_cast<std::uint16_t>(datagram[portOffset + 1]));
    if (port == 0) {
        return Socks5UdpParseResult::InvalidPort;
    }

    const std::size_t payloadOffset = portOffset + 2;
    output.addressType = addressType;
    output.address = datagram + addressOffset;
    output.addressLength = addressLength;
    output.port = port;
    output.payload = datagram + payloadOffset;
    output.payloadLength = datagramLength - payloadOffset;
    return Socks5UdpParseResult::Valid;
}

} // namespace furious::wfp::broker
