#pragma once

// Pointer-free ABI shared by the WFP kernel driver and elevated service.
// Keep numeric values stable across driver/service upgrades. The kernel build
// must use WDK types and must never pull the user-mode CRT headers into WDK.
#if defined(FURIOUS_WFP_KERNEL_MODE)
#include <ntdef.h>
typedef ULONG FURIOUS_WFP_UINT32;
#else
#include <stdint.h>
typedef uint32_t FURIOUS_WFP_UINT32;
#endif

#define FURIOUS_WFP_DRIVER_ABI_VERSION 1u
#define FURIOUS_WFP_DRIVER_IOCTL_QUERY_STATUS 0x00226000UL
#define FURIOUS_WFP_DRIVER_IOCTL_SET_ENDPOINT_CONFIG 0x00226004UL
#define FURIOUS_WFP_DRIVER_IOCTL_CLEAR_ENDPOINT_CONFIG 0x00226008UL

#define FURIOUS_WFP_DRIVER_FLAG_CALLOUT_REGISTERED 0x00000001u
#define FURIOUS_WFP_DRIVER_FLAG_ENDPOINT_CONFIGURED 0x00000002u

#pragma pack(push, 1)
typedef struct FURIOUS_WFP_DRIVER_STATUS {
    FURIOUS_WFP_UINT32 Size;
    FURIOUS_WFP_UINT32 Version;
    FURIOUS_WFP_UINT32 Flags;
    FURIOUS_WFP_UINT32 Reserved;
} FURIOUS_WFP_DRIVER_STATUS;
#pragma pack(pop)
