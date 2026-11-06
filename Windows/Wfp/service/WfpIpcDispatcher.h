#pragma once

#include <windows.h>

#include "../include/WfpControlProtocol.h"
#include "WfpPolicyValidator.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace furious::wfp::ipc {

class PolicyStore final {
public:
    DWORD Set(const void* data, size_t size) noexcept {
        if (furious::wfp::policy::ValidatePolicy(data, size) !=
            furious::wfp::policy::ValidationResult::Valid) {
            return ERROR_INVALID_DATA;
        }

        FURIOUS_WFP_POLICY_HEADER header = {};
        std::memcpy(&header, data, sizeof(header));

        std::vector<uint8_t> candidate;
        try {
            const auto* first = static_cast<const uint8_t*>(data);
            candidate.assign(first, first + size);
        } catch (...) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (header.PolicyGeneration <= generation_) {
            return ERROR_REVISION_MISMATCH;
        }
        policy_.swap(candidate);
        generation_ = header.PolicyGeneration;
        return ERROR_SUCCESS;
    }

    DWORD Clear() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        policy_.clear();
        return ERROR_SUCCESS;
    }

private:
    std::mutex mutex_;
    std::vector<uint8_t> policy_;
    uint64_t generation_ = 0;
};

inline PolicyStore& GetPolicyStore() noexcept {
    static PolicyStore store;
    return store;
}

inline DWORD DispatchCommand(uint32_t command,
                             const void* payload,
                             size_t payloadSize) noexcept {
    switch (command) {
    case FURIOUS_WFP_IPC_COMMAND_STATUS:
        return payloadSize == 0 ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
    case FURIOUS_WFP_IPC_COMMAND_SET_POLICY:
        if (payload == nullptr || payloadSize == 0) {
            return ERROR_INVALID_DATA;
        }
        return GetPolicyStore().Set(payload, payloadSize);
    case FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY:
        if (payloadSize != 0) {
            return ERROR_INVALID_PARAMETER;
        }
        return GetPolicyStore().Clear();
    default:
        return ERROR_INVALID_FUNCTION;
    }
}

} // namespace furious::wfp::ipc
