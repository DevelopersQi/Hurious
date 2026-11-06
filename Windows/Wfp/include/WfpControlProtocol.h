#pragma once

// Stable, pointer-free control-plane message ABI for the local WFP service.
// Transport security (named-pipe ACL + client token authorization) is mandatory;
// validating this structure alone does not authenticate a caller.

#include <stddef.h>
#include <stdint.h>
#include "WfpBrokerProtocol.h"

#define FURIOUS_WFP_IPC_MAGIC 0x46575043u /* "FWPC" */
#define FURIOUS_WFP_IPC_VERSION 2u
#define FURIOUS_WFP_IPC_MAX_MESSAGE_SIZE (64u * 1024u)

#define FURIOUS_WFP_IPC_COMMAND_STATUS 1u
#define FURIOUS_WFP_IPC_COMMAND_SET_POLICY 2u
#define FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY 3u
#define FURIOUS_WFP_IPC_COMMAND_DRIVER_STATUS 4u
#define FURIOUS_WFP_IPC_COMMAND_SET_ENDPOINT_CONFIG 5u
#define FURIOUS_WFP_IPC_COMMAND_CLEAR_ENDPOINT_CONFIG 6u
#define FURIOUS_WFP_IPC_COMMAND_START_BROKER 7u
#define FURIOUS_WFP_IPC_COMMAND_STOP_BROKER 8u

#pragma pack(push, 1)
typedef struct FURIOUS_WFP_IPC_HEADER {
    uint32_t Magic;
    uint16_t Version;
    uint16_t HeaderSize;
    uint32_t TotalSize;
    uint32_t Command;
    uint64_t RequestId;
} FURIOUS_WFP_IPC_HEADER;

typedef struct FURIOUS_WFP_IPC_RESPONSE {
    FURIOUS_WFP_IPC_HEADER Header;
    uint32_t Win32Status;
    uint32_t ServiceState;
    uint32_t BrokerProcessId;
    uint16_t TcpPortV4;
    uint16_t TcpPortV6;
} FURIOUS_WFP_IPC_RESPONSE;
#pragma pack(pop)

#ifdef __cplusplus
#include <cstddef>

namespace furious::wfp::ipc {

static_assert(sizeof(FURIOUS_WFP_IPC_RESPONSE) == 40, "IPC response ABI must be 40 bytes");

enum class ValidationResult {
    Valid,
    NullMessage,
    MessageTooSmall,
    MessageTooLarge,
    InvalidMagic,
    UnsupportedVersion,
    InvalidHeaderSize,
    InvalidTotalSize,
    UnsupportedCommand
};

inline ValidationResult ValidateRequest(const void* message, size_t messageSize) noexcept {
    if (message == nullptr) {
        return ValidationResult::NullMessage;
    }
    if (messageSize < sizeof(FURIOUS_WFP_IPC_HEADER)) {
        return ValidationResult::MessageTooSmall;
    }
    if (messageSize > FURIOUS_WFP_IPC_MAX_MESSAGE_SIZE) {
        return ValidationResult::MessageTooLarge;
    }

    FURIOUS_WFP_IPC_HEADER header = {};
    const auto* bytes = static_cast<const uint8_t*>(message);
    auto* destination = reinterpret_cast<uint8_t*>(&header);
    for (size_t i = 0; i < sizeof(header); ++i) {
        destination[i] = bytes[i];
    }

    if (header.Magic != FURIOUS_WFP_IPC_MAGIC) {
        return ValidationResult::InvalidMagic;
    }
    if (header.Version != FURIOUS_WFP_IPC_VERSION) {
        return ValidationResult::UnsupportedVersion;
    }
    if (header.HeaderSize != sizeof(FURIOUS_WFP_IPC_HEADER)) {
        return ValidationResult::InvalidHeaderSize;
    }
    if (header.TotalSize != messageSize ||
        header.TotalSize < header.HeaderSize ||
        header.TotalSize > FURIOUS_WFP_IPC_MAX_MESSAGE_SIZE) {
        return ValidationResult::InvalidTotalSize;
    }
    if (header.Command != FURIOUS_WFP_IPC_COMMAND_STATUS &&
        header.Command != FURIOUS_WFP_IPC_COMMAND_SET_POLICY &&
        header.Command != FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY &&
        header.Command != FURIOUS_WFP_IPC_COMMAND_DRIVER_STATUS &&
        header.Command != FURIOUS_WFP_IPC_COMMAND_SET_ENDPOINT_CONFIG &&
        header.Command != FURIOUS_WFP_IPC_COMMAND_CLEAR_ENDPOINT_CONFIG &&
        header.Command != FURIOUS_WFP_IPC_COMMAND_START_BROKER &&
        header.Command != FURIOUS_WFP_IPC_COMMAND_STOP_BROKER) {
        return ValidationResult::UnsupportedCommand;
    }
    return ValidationResult::Valid;
}

} // namespace furious::wfp::ipc
#endif
