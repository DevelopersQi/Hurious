#pragma once

// Stable user-mode / kernel-mode policy ABI for Furious WFP.
// Keep this header C-compatible: it is consumed by the WDK driver and service.

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FURIOUS_WFP_POLICY_ABI_VERSION 1u
#define FURIOUS_WFP_MAX_RULES 256u
#define FURIOUS_WFP_MAX_IMAGE_PATH_CHARS 520u

typedef enum FURIOUS_WFP_ACTION {
    FuriousWfpActionUnspecified = 0,
    FuriousWfpActionProxy = 1,
    FuriousWfpActionDirect = 2
} FURIOUS_WFP_ACTION;

typedef enum FURIOUS_WFP_BACKEND {
    FuriousWfpBackendNone = 0,
    FuriousWfpBackendXray = 1,
    FuriousWfpBackendHysteria2 = 2,
    FuriousWfpBackendTun2socks = 3
} FURIOUS_WFP_BACKEND;

typedef struct FURIOUS_WFP_APPLICATION_RULE {
    uint32_t Size;
    uint32_t Priority;
    uint32_t Enabled;
    uint32_t Action;
    uint32_t ImagePathChars;
    wchar_t ImagePath[FURIOUS_WFP_MAX_IMAGE_PATH_CHARS];
} FURIOUS_WFP_APPLICATION_RULE;

typedef struct FURIOUS_WFP_POLICY_HEADER {
    uint32_t Size;
    uint32_t AbiVersion;
    uint32_t RuleCount;
    uint32_t Backend;
    uint64_t PolicyGeneration;
} FURIOUS_WFP_POLICY_HEADER;

// All policy transfers are versioned and size-checked. Unknown ABI versions,
// oversized rule counts, invalid actions and malformed paths must be rejected.

#ifdef __cplusplus
}
#endif
