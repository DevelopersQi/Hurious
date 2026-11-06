#pragma once

// Shared ABI for the WFP redirect endpoint and original-destination context.
// The driver owns redirect-context memory after it is attached to
// FWPS_CONNECT_REQUEST0. A local proxy retrieves it with
// SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT and must also preserve redirect
// records on any proxy-created outbound socket.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FURIOUS_WFP_REDIRECT_ABI_VERSION 1u
#define FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC 0x46575243u /* "FWRC" */

#define FURIOUS_WFP_REDIRECT_FAMILY_V4 4u
#define FURIOUS_WFP_REDIRECT_FAMILY_V6 6u

#define FURIOUS_WFP_REDIRECT_PROTOCOL_TCP 6u
#define FURIOUS_WFP_REDIRECT_PROTOCOL_UDP 17u

#define FURIOUS_WFP_REDIRECT_FLAG_IPV4 0x00000001u
#define FURIOUS_WFP_REDIRECT_FLAG_IPV6 0x00000002u
#define FURIOUS_WFP_REDIRECT_FLAG_TCP  0x00000004u
#define FURIOUS_WFP_REDIRECT_FLAG_UDP  0x00000008u
#define FURIOUS_WFP_REDIRECT_KNOWN_FLAGS 0x0000000Fu

#pragma pack(push, 1)
typedef struct FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG {
    uint32_t Size;
    uint32_t AbiVersion;
    uint32_t Backend;
    uint32_t Flags;
    uint32_t ProxyProcessId;
    uint32_t Reserved0;
    uint64_t PolicyGeneration;
    uint16_t TcpPortV4; // host byte order; loopback address is 127.0.0.1
    uint16_t UdpPortV4; // host byte order; loopback address is 127.0.0.1
    uint16_t TcpPortV6; // host byte order; loopback address is ::1
    uint16_t UdpPortV6; // host byte order; loopback address is ::1
} FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG;

// This structure is opaque to WFP and is returned to the local proxy through
// SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT. Address bytes and port are in
// network byte order; IPv4 uses the first four address bytes.
typedef struct FURIOUS_WFP_REDIRECT_CONTEXT {
    uint32_t Magic;
    uint32_t Size;
    uint16_t AbiVersion;
    uint16_t AddressFamily;
    uint8_t Protocol;
    uint8_t Flags;
    uint16_t OriginalPortNetworkOrder;
    uint8_t OriginalAddress[16];
    uint32_t OriginalProcessId;
    uint32_t RulePriority;
    uint64_t PolicyGeneration;
    uint32_t Reserved[4];
} FURIOUS_WFP_REDIRECT_CONTEXT;
#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
#include <cstddef>

namespace furious::wfp::redirect {

inline bool IsValidEndpointConfig(
    const FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG& value) noexcept {
    if (value.Size != sizeof(value) ||
        value.AbiVersion != FURIOUS_WFP_REDIRECT_ABI_VERSION ||
        value.Backend < 1u || value.Backend > 3u ||
        value.ProxyProcessId == 0 ||
        value.PolicyGeneration == 0 ||
        value.Reserved0 != 0 ||
        (value.Flags & ~FURIOUS_WFP_REDIRECT_KNOWN_FLAGS) != 0 ||
        (value.Flags & (FURIOUS_WFP_REDIRECT_FLAG_IPV4 |
                        FURIOUS_WFP_REDIRECT_FLAG_IPV6 |
                        FURIOUS_WFP_REDIRECT_FLAG_TCP |
                        FURIOUS_WFP_REDIRECT_FLAG_UDP)) == 0) {
        return false;
    }

    const bool v4 = (value.Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV4) != 0;
    const bool v6 = (value.Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV6) != 0;
    const bool tcp = (value.Flags & FURIOUS_WFP_REDIRECT_FLAG_TCP) != 0;
    const bool udp = (value.Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) != 0;

    if ((v4 && tcp) != (value.TcpPortV4 != 0) ||
        (v4 && udp) != (value.UdpPortV4 != 0) ||
        (v6 && tcp) != (value.TcpPortV6 != 0) ||
        (v6 && udp) != (value.UdpPortV6 != 0)) {
        return false;
    }
    if ((!v4 && (value.TcpPortV4 != 0 || value.UdpPortV4 != 0)) ||
        (!v6 && (value.TcpPortV6 != 0 || value.UdpPortV6 != 0)) ||
        (!tcp && (value.TcpPortV4 != 0 || value.TcpPortV6 != 0)) ||
        (!udp && (value.UdpPortV4 != 0 || value.UdpPortV6 != 0))) {
        return false;
    }
    return true;
}

inline bool IsValidRedirectContext(
    const FURIOUS_WFP_REDIRECT_CONTEXT& value) noexcept {
    if (value.Magic != FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC ||
        value.Size != sizeof(value) ||
        value.AbiVersion != FURIOUS_WFP_REDIRECT_ABI_VERSION ||
        (value.AddressFamily != FURIOUS_WFP_REDIRECT_FAMILY_V4 &&
         value.AddressFamily != FURIOUS_WFP_REDIRECT_FAMILY_V6) ||
        (value.Protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_TCP &&
         value.Protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_UDP) ||
        value.OriginalPortNetworkOrder == 0 ||
        value.OriginalProcessId == 0 ||
        value.PolicyGeneration == 0 ||
        value.Flags != 0) {
        return false;
    }
    for (uint32_t reserved : value.Reserved) {
        if (reserved != 0) {
            return false;
        }
    }
    if (value.AddressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4) {
        for (size_t i = 4; i < sizeof(value.OriginalAddress); ++i) {
            if (value.OriginalAddress[i] != 0) {
                return false;
            }
        }
    }
    return true;
}

} // namespace furious::wfp::redirect
#endif
