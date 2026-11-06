#pragma once

// Pointer-free ABI shared by the WFP kernel driver and elevated service.
// Keep numeric values stable across driver/service upgrades.
#include <stdint.h>

#define FURIOUS_WFP_DRIVER_ABI_VERSION 1u
#define FURIOUS_WFP_DRIVER_IOCTL_QUERY_STATUS 0x00226000UL

#define FURIOUS_WFP_DRIVER_FLAG_CALLOUT_REGISTERED 0x00000001u

#pragma pack(push, 1)
typedef struct FURIOUS_WFP_DRIVER_STATUS {
    uint32_t Size;
    uint32_t Version;
    uint32_t Flags;
    uint32_t Reserved;
} FURIOUS_WFP_DRIVER_STATUS;
#pragma pack(pop)
