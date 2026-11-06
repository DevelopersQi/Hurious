#pragma once

#include <stdint.h>

#define FURIOUS_WFP_BROKER_ABI_VERSION 1u
#define FURIOUS_WFP_BROKER_FLAG_LISTEN_IPV4 0x0001u
#define FURIOUS_WFP_BROKER_FLAG_LISTEN_IPV6 0x0002u
#define FURIOUS_WFP_BROKER_KNOWN_FLAGS 0x0003u
#define FURIOUS_WFP_BROKER_FAMILY_IPV4 4u
#define FURIOUS_WFP_BROKER_FAMILY_IPV6 6u

#pragma pack(push, 1)
typedef struct FURIOUS_WFP_BROKER_START_REQUEST {
    uint32_t Size;
    uint32_t AbiVersion;
    uint16_t SocksAddressFamily;
    uint16_t Flags;
    uint16_t SocksPort;
    uint16_t Reserved;
    uint8_t SocksAddress[16];
} FURIOUS_WFP_BROKER_START_REQUEST;
#pragma pack(pop)

#ifdef __cplusplus
static_assert(sizeof(FURIOUS_WFP_BROKER_START_REQUEST) == 32,
              "Broker start ABI must be 32 bytes");
#endif
