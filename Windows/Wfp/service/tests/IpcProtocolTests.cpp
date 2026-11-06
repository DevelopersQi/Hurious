#include "../../include/WfpControlProtocol.h"
#include "../WfpIpcDispatcher.h"
#include "../WfpPolicyValidator.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::fprintf(stderr, "Check failed at line %d: %s\\n", __LINE__, #condition); \
        return 1; \
    } \
} while (0)

int main() {
    using furious::wfp::ipc::ValidateRequest;
    using furious::wfp::ipc::ValidationResult;

    FURIOUS_WFP_IPC_HEADER request = {};
    request.Magic = FURIOUS_WFP_IPC_MAGIC;
    request.Version = FURIOUS_WFP_IPC_VERSION;
    request.HeaderSize = sizeof(request);
    request.TotalSize = sizeof(request);
    request.Command = FURIOUS_WFP_IPC_COMMAND_STATUS;
    request.RequestId = 42;

    CHECK(ValidateRequest(&request, sizeof(request)) == ValidationResult::Valid);
    CHECK(ValidateRequest(nullptr, sizeof(request)) == ValidationResult::NullMessage);
    CHECK(ValidateRequest(&request, sizeof(request) - 1) == ValidationResult::MessageTooSmall);

    auto invalid = request;
    invalid.Magic = 0;
    CHECK(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::InvalidMagic);

    invalid = request;
    invalid.Version = 99;
    CHECK(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::UnsupportedVersion);

    invalid = request;
    invalid.HeaderSize--;
    CHECK(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::InvalidHeaderSize);

    invalid = request;
    invalid.TotalSize++;
    CHECK(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::InvalidTotalSize);

    invalid = request;
    invalid.Command = 0xFFFFFFFFu;
    CHECK(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::UnsupportedCommand);

    std::array<uint8_t, FURIOUS_WFP_IPC_MAX_MESSAGE_SIZE + 1> oversized = {};
    CHECK(ValidateRequest(oversized.data(), oversized.size()) == ValidationResult::MessageTooLarge);

    using furious::wfp::ipc::DispatchCommand;
    using furious::wfp::ipc::CopyPolicySnapshot;
    CHECK(DispatchCommand(FURIOUS_WFP_IPC_COMMAND_STATUS, nullptr, 0) == ERROR_SUCCESS);
    CHECK(DispatchCommand(FURIOUS_WFP_IPC_COMMAND_SET_POLICY, nullptr, 0) == ERROR_INVALID_DATA);
    CHECK(DispatchCommand(FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY, nullptr, 0) == ERROR_SUCCESS);
    CHECK(CopyPolicySnapshot(policySnapshot, &storedGeneration) == ERROR_SUCCESS);
    CHECK(policySnapshot.empty());
    CHECK(storedGeneration == 1);
    CHECK(DispatchCommand(0xFFFFFFFFu, nullptr, 0) == ERROR_INVALID_FUNCTION);

    using furious::wfp::policy::ValidatePolicy;
    using PolicyValidationResult = furious::wfp::policy::ValidationResult;
    FURIOUS_WFP_POLICY_HEADER policyHeader = {};
    policyHeader.Size = sizeof(policyHeader);
    policyHeader.AbiVersion = FURIOUS_WFP_POLICY_ABI_VERSION;
    policyHeader.RuleCount = 1;
    policyHeader.Backend = FuriousWfpBackendXray;
    policyHeader.PolicyGeneration = 1;
    FURIOUS_WFP_APPLICATION_RULE policyRule = {};
    policyRule.Size = sizeof(policyRule);
    policyRule.Priority = 10;
    policyRule.Enabled = 1;
    policyRule.Action = FuriousWfpActionProxy;
    const wchar_t imagePath[] = L"C:\\Program Files\\Furious\\app.exe";
    policyRule.ImagePathChars = static_cast<uint32_t>((sizeof(imagePath) / sizeof(imagePath[0])) - 1);
    std::memcpy(policyRule.ImagePath, imagePath, sizeof(imagePath));
    std::array<uint8_t, sizeof(policyHeader) + sizeof(policyRule)> policyBytes = {};
    std::memcpy(policyBytes.data(), &policyHeader, sizeof(policyHeader));
    std::memcpy(policyBytes.data() + sizeof(policyHeader), &policyRule, sizeof(policyRule));
    CHECK(ValidatePolicy(policyBytes.data(), policyBytes.size()) == PolicyValidationResult::Valid);
    CHECK(DispatchCommand(FURIOUS_WFP_IPC_COMMAND_SET_POLICY,
                          policyBytes.data(), policyBytes.size()) == ERROR_SUCCESS);
    std::vector<uint8_t> policySnapshot;
    uint64_t storedGeneration = 0;
    CHECK(CopyPolicySnapshot(policySnapshot, &storedGeneration) == ERROR_SUCCESS);
    CHECK(policySnapshot.size() == policyBytes.size());
    CHECK(storedGeneration == 1);
    CHECK(DispatchCommand(FURIOUS_WFP_IPC_COMMAND_SET_POLICY,
                          policyBytes.data(), policyBytes.size()) == ERROR_REVISION_MISMATCH);
    CHECK(DispatchCommand(FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY,
                          nullptr, 0) == ERROR_SUCCESS);
    CHECK(ValidatePolicy(nullptr, policyBytes.size()) == PolicyValidationResult::NullPolicy);
    auto missingBackend = policyBytes;
    policyHeader.Backend = FuriousWfpBackendNone;
    std::memcpy(missingBackend.data(), &policyHeader, sizeof(policyHeader));
    CHECK(ValidatePolicy(missingBackend.data(), missingBackend.size()) ==
          PolicyValidationResult::ProxyBackendRequired);
    policyHeader.Backend = FuriousWfpBackendXray;
    auto zeroGeneration = policyBytes;
    policyHeader.PolicyGeneration = 0;
    std::memcpy(zeroGeneration.data(), &policyHeader, sizeof(policyHeader));
    CHECK(ValidatePolicy(zeroGeneration.data(), zeroGeneration.size()) ==
          PolicyValidationResult::InvalidPolicyGeneration);
    policyHeader.PolicyGeneration = 1;
    auto badPolicy = policyBytes;
    policyHeader.RuleCount = FURIOUS_WFP_MAX_RULES + 1;
    std::memcpy(badPolicy.data(), &policyHeader, sizeof(policyHeader));
    policyHeader.RuleCount = 1;
    CHECK(ValidatePolicy(badPolicy.data(), badPolicy.size()) == PolicyValidationResult::TooManyRules);
    badPolicy = policyBytes;
    FURIOUS_WFP_APPLICATION_RULE badRule = policyRule;
    badRule.ImagePath[1] = L'!';
    std::memcpy(badPolicy.data() + sizeof(policyHeader), &badRule, sizeof(badRule));
    CHECK(ValidatePolicy(badPolicy.data(), badPolicy.size()) == PolicyValidationResult::PathNotAbsolute);
    badPolicy = policyBytes;
    badRule = policyRule;
    badRule.Action = 99;
    std::memcpy(badPolicy.data() + sizeof(policyHeader), &badRule, sizeof(badRule));
    CHECK(ValidatePolicy(badPolicy.data(), badPolicy.size()) == PolicyValidationResult::InvalidAction);
    return 0;
}
