#include "../..//include/WfpControlProtocol.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>

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

    assert(ValidateRequest(&request, sizeof(request)) == ValidationResult::Valid);
    assert(ValidateRequest(nullptr, sizeof(request)) == ValidationResult::NullMessage);
    assert(ValidateRequest(&request, sizeof(request) - 1) == ValidationResult::MessageTooSmall);

    auto invalid = request;
    invalid.Magic = 0;
    assert(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::InvalidMagic);

    invalid = request;
    invalid.Version = 99;
    assert(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::UnsupportedVersion);

    invalid = request;
    invalid.HeaderSize--;
    assert(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::InvalidHeaderSize);

    invalid = request;
    invalid.TotalSize++;
    assert(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::InvalidTotalSize);

    invalid = request;
    invalid.Command = 0xFFFFFFFFu;
    assert(ValidateRequest(&invalid, sizeof(invalid)) == ValidationResult::UnsupportedCommand);

    std::array<uint8_t, FURIOUS_WFP_IPC_MAX_MESSAGE_SIZE + 1> oversized = {};
    assert(ValidateRequest(oversized.data(), oversized.size()) == ValidationResult::MessageTooLarge);
    return 0;
}
