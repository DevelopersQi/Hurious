#pragma once

#include <windows.h>

#include "../include/WfpControlProtocol.h"
#include "WfpDriverClient.h"
#include "WfpPolicyCompiler.h"

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
        std::vector<furious::wfp::policy::CompiledApplicationRule> compiledCandidate;
        try {
            const auto* first = static_cast<const uint8_t*>(data);
            candidate.assign(first, first + size);
        } catch (...) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }

        const DWORD compileStatus = furious::wfp::policy::CompilePolicy(
            data, size, compiledCandidate);
        if (compileStatus != ERROR_SUCCESS) {
            return compileStatus;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (header.PolicyGeneration <= generation_) {
            return ERROR_REVISION_MISMATCH;
        }
        policy_.swap(candidate);
        compiledPolicy_.swap(compiledCandidate);
        generation_ = header.PolicyGeneration;
        return ERROR_SUCCESS;
    }

    DWORD CopySnapshot(std::vector<uint8_t>& output, uint64_t* generation = nullptr) const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        try {
            output = policy_;
        } catch (...) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        if (generation != nullptr) {
            *generation = generation_;
        }
        return ERROR_SUCCESS;
    }

    DWORD CopyCompiledSnapshot(
        std::vector<furious::wfp::policy::CompiledApplicationRule>& output) const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        try {
            output = compiledPolicy_;
        } catch (...) {
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        return ERROR_SUCCESS;
    }

    DWORD Clear() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        policy_.clear();
        compiledPolicy_.clear();
        return ERROR_SUCCESS;
    }

private:
    mutable std::mutex mutex_;
    std::vector<uint8_t> policy_;
    std::vector<furious::wfp::policy::CompiledApplicationRule> compiledPolicy_;
    uint64_t generation_ = 0;
};

inline PolicyStore& GetPolicyStore() noexcept {
    static PolicyStore store;
    return store;
}

inline DWORD CopyPolicySnapshot(std::vector<uint8_t>& output,
                                uint64_t* generation = nullptr) noexcept {
    return GetPolicyStore().CopySnapshot(output, generation);
}

inline DWORD CopyCompiledPolicySnapshot(
    std::vector<furious::wfp::policy::CompiledApplicationRule>& output) noexcept {
    return GetPolicyStore().CopyCompiledSnapshot(output);
}

inline DWORD DispatchCommand(uint32_t command,
                             const void* payload,
                             size_t payloadSize) noexcept {
    switch (command) {
    case FURIOUS_WFP_IPC_COMMAND_STATUS:
        return payloadSize == 0 ? ERROR_SUCCESS : ERROR_INVALID_PARAMETER;
    case FURIOUS_WFP_IPC_COMMAND_DRIVER_STATUS: {
        if (payloadSize != 0) {
            return ERROR_INVALID_PARAMETER;
        }
        FURIOUS_WFP_DRIVER_STATUS status = {};
        return furious::wfp::driver::QueryStatus(&status);
    }
    case FURIOUS_WFP_IPC_COMMAND_SET_ENDPOINT_CONFIG: {
        if (payload == nullptr ||
            payloadSize != sizeof(FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG)) {
            return ERROR_INVALID_DATA;
        }
        FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG config = {};
        std::memcpy(&config, payload, sizeof(config));
        return furious::wfp::driver::SetEndpointConfig(config);
    }
    case FURIOUS_WFP_IPC_COMMAND_CLEAR_ENDPOINT_CONFIG:
        if (payloadSize != 0) {
            return ERROR_INVALID_PARAMETER;
        }
        return furious::wfp::driver::ClearEndpointConfig();
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
