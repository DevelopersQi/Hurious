#include "WfpSocks5Udp.h"

namespace furious::wfp::broker {

Socks5UdpBuildResult BuildSocks5UdpDatagram(
    Socks5UdpAddressType addressType,
    const std::uint8_t* address,
    std::size_t addressLength,
    std::uint16_t port,
    const std::uint8_t* payload,
    std::size_t payloadLength,
    std::vector<std::uint8_t>& output,
    std::size_t maximumDatagramLength) noexcept {
    output.clear();
    if (address == nullptr) return Socks5UdpBuildResult::NullAddress;
    if (payload == nullptr && payloadLength != 0) return Socks5UdpBuildResult::NullPayload;
    if (port == 0) return Socks5UdpBuildResult::InvalidPort;

    std::size_t addressPrefixLength = 0;
    switch (addressType) {
    case Socks5UdpAddressType::Ipv4:
        if (addressLength != 4) return Socks5UdpBuildResult::InvalidAddressLength;
        addressPrefixLength = 4;
        break;
    case Socks5UdpAddressType::Ipv6:
        if (addressLength != 16) return Socks5UdpBuildResult::InvalidAddressLength;
        addressPrefixLength = 16;
        break;
    case Socks5UdpAddressType::Domain:
        if (addressLength == 0) return Socks5UdpBuildResult::EmptyDomain;
        if (addressLength > 255) return Socks5UdpBuildResult::InvalidAddressLength;
        addressPrefixLength = 1 + addressLength;
        break;
    default:
        return Socks5UdpBuildResult::InvalidAddressType;
    }

    const std::size_t headerLength = 4 + addressPrefixLength + 2;
    const std::size_t maximumLength =
        maximumDatagramLength < kMaximumSocks5UdpDatagramSize
            ? maximumDatagramLength : kMaximumSocks5UdpDatagramSize;
    if (headerLength > maximumLength ||
        payloadLength > maximumLength - headerLength) {
        return Socks5UdpBuildResult::DatagramTooLarge;
    }

    try {
        output.reserve(headerLength + payloadLength);
        output.insert(output.end(), {0, 0, 0, static_cast<std::uint8_t>(addressType)});
        if (addressType == Socks5UdpAddressType::Domain) {
            output.push_back(static_cast<std::uint8_t>(addressLength));
        }
        output.insert(output.end(), address, address + addressLength);
        output.push_back(static_cast<std::uint8_t>((port >> 8) & 0xFF));
        output.push_back(static_cast<std::uint8_t>(port & 0xFF));
        if (payloadLength != 0) output.insert(output.end(), payload, payload + payloadLength);
    } catch (...) {
        output.clear();
        return Socks5UdpBuildResult::AllocationFailure;
    }
    return Socks5UdpBuildResult::Valid;
}

Socks5UdpParseResult ParseSocks5UdpDatagram(
    const std::uint8_t* datagram,
    std::size_t datagramLength,
    Socks5UdpDatagramView& output) noexcept {
    output = Socks5UdpDatagramView{};
    if (datagram == nullptr) {
        return Socks5UdpParseResult::NullDatagram;
    }
    // The fixed SOCKS5 UDP prefix is RSV(2) + FRAG(1) + ATYP(1).
    // Address- and port-specific truncation is checked after ATYP decoding.
    if (datagramLength < 4) {
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
