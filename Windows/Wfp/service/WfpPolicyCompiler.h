#pragma once

#include "../include/ApplicationRoutingPolicy.h"\n#include "WfpPolicyValidator.h"

#include <windows.h>
#include <fwpmu.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <utility>
#include <vector>

namespace furious::wfp::policy {

struct CompiledApplicationRule final {
    uint32_t Priority = 0;
    uint32_t Action = FuriousWfpActionDirect;
    uint32_t Backend = FuriousWfpBackendNone;
    std::vector<uint8_t> AppId;
};

inline DWORD ResolveApplicationId(const wchar_t* imagePath,
                                  std::vector<uint8_t>& output) noexcept {
    if (imagePath == nullptr || imagePath[0] == L'\\0') {
        return ERROR_INVALID_PARAMETER;
    }

    FWP_BYTE_BLOB* appId = nullptr;
    const DWORD status = FwpmGetAppIdFromFileName0(imagePath, &appId);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    if (appId == nullptr || appId->data == nullptr || appId->size == 0) {
        if (appId != nullptr) {
            FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
        }
        return ERROR_INVALID_DATA;
    }

    std::vector<uint8_t> candidate;
    try {
        candidate.assign(appId->data, appId->data + appId->size);
    } catch (...) {
        FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
    output.swap(candidate);
    return ERROR_SUCCESS;
}

// Compiles the complete policy before publishing it. Disabled rules are
// omitted; an invalid or missing executable leaves output untouched.
inline DWORD CompilePolicy(const void* data, size_t bytes,
                           std::vector<CompiledApplicationRule>& output) noexcept {
    if (ValidatePolicy(data, bytes) != ValidationResult::Valid) {
        return ERROR_INVALID_DATA;
    }

    FURIOUS_WFP_POLICY_HEADER header = {};
    std::memcpy(&header, data, sizeof(header));
    const auto* raw = static_cast<const uint8_t*>(data);
    std::vector<CompiledApplicationRule> candidate;

    try {
        candidate.reserve(header.RuleCount);
        for (uint32_t index = 0; index < header.RuleCount; ++index) {
            FURIOUS_WFP_APPLICATION_RULE rule = {};
            std::memcpy(&rule,
                        raw + sizeof(header) +
                            static_cast<size_t>(index) * sizeof(rule),
                        sizeof(rule));
            if (rule.Enabled == 0) {
                continue;
            }

            CompiledApplicationRule compiled;
            compiled.Priority = rule.Priority;
            compiled.Action = rule.Action;
            compiled.Backend = rule.Action == FuriousWfpActionProxy
                ? header.Backend : FuriousWfpBackendNone;

            const DWORD status = ResolveApplicationId(rule.ImagePath, compiled.AppId);
            if (status != ERROR_SUCCESS) {
                return status;
            }
            candidate.emplace_back(std::move(compiled));
        }
    } catch (const std::bad_alloc&) {
        return ERROR_NOT_ENOUGH_MEMORY;
    } catch (...) {
        return ERROR_INVALID_DATA;
    }

    output.swap(candidate);
    return ERROR_SUCCESS;
}

} // namespace furious::wfp::policy
