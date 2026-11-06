#pragma once

// Shared ABI for the WFP redirect endpoint and original-destination context.
// The driver owns redirect-context memory after it is attached to
// FWPS_CONNECT_REQUEST0. A local proxy retrieves it with
// SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT and must also preserve redirect
// records on any proxy-created outbound socket.

#if defined(FURIOUS_WFP_KERNEL_MODE)
#include <ntdef.h>
typedef UCHAR FURIOUS_WFP_U8;
typedef USHORT FURIOUS_WFP_U16;
typedef ULONG FURIOUS_WFP_U32;
typedef ULONGLONG FURIOUS_WFP_U64;
#else
#include <stdint.h>
typedef uint8_t FURIOUS_WFP_U8;
typedef uint16_t FURIOUS_WFP_U16;
typedef uint32_t FURIOUS_WFP_U32;
typedef uint64_t FURIOUS_WFP_U64;
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define FURIOUS_WFP_REDIRECT_ABI_VERSION 2u
#define FURIOUS_WFP_MAX_EXCLUDED_PROCESS_IDS 8u
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
    FURIOUS_WFP_U32 Size;
    FURIOUS_WFP_U32 AbiVersion;
    FURIOUS_WFP_U32 Backend;
    FURIOUS_WFP_U32 Flags;
    FURIOUS_WFP_U32 ProxyProcessId;
    FURIOUS_WFP_U32 Reserved0;
    FURIOUS_WFP_U64 PolicyGeneration;
    FURIOUS_WFP_U16 TcpPortV4; // host byte order; loopback address is 127.0.0.1
    FURIOUS_WFP_U16 UdpPortV4; // host byte order; loopback address is 127.0.0.1
    FURIOUS_WFP_U16 TcpPortV6; // host byte order; loopback address is ::1
    FURIOUS_WFP_U16 UdpPortV6; // host byte order; loopback address is ::1
    FURIOUS_WFP_U32 ExcludedProcessCount;
    FURIOUS_WFP_U32 ExcludedProcessIds[FURIOUS_WFP_MAX_EXCLUDED_PROCESS_IDS];
} FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG;

// This structure is opaque to WFP and is returned to the local proxy through
// SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT. Address bytes and port are in
// network byte order; IPv4 uses the first four address bytes.
typedef struct FURIOUS_WFP_REDIRECT_CONTEXT {
    FURIOUS_WFP_U32 Magic;
    FURIOUS_WFP_U32 Size;
    FURIOUS_WFP_U16 AbiVersion;
    FURIOUS_WFP_U16 AddressFamily;
    FURIOUS_WFP_U8 Protocol;
    FURIOUS_WFP_U8 Flags;
    FURIOUS_WFP_U16 OriginalPortNetworkOrder;
    FURIOUS_WFP_U8 OriginalAddress[16];
    FURIOUS_WFP_U32 OriginalProcessId;
    FURIOUS_WFP_U32 RulePriority;
    FURIOUS_WFP_U64 PolicyGeneration;
    FURIOUS_WFP_U32 Reserved[4];
} FURIOUS_WFP_REDIRECT_CONTEXT;
#pragma pack(pop)

#ifdef __cplusplus
}
#endif

#if defined(__cplusplus) && !defined(FURIOUS_WFP_KERNEL_MODE)
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
        value.ExcludedProcessCount > FURIOUS_WFP_MAX_EXCLUDED_PROCESS_IDS ||
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
    for (FURIOUS_WFP_U32 i = 0; i < FURIOUS_WFP_MAX_EXCLUDED_PROCESS_IDS; ++i) {
        const FURIOUS_WFP_U32 processId = value.ExcludedProcessIds[i];
        if (i < value.ExcludedProcessCount) {
            if (processId == 0 || processId == value.ProxyProcessId) {
                return false;
            }
            for (FURIOUS_WFP_U32 previous = 0; previous < i; ++previous) {
                if (value.ExcludedProcessIds[previous] == processId) {
                    return false;
                }
            }
        } else if (processId != 0) {
            return false;
        }
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
    for (FURIOUS_WFP_U32 reserved : value.Reserved) {
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
