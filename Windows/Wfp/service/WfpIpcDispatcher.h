#pragma once

#include <windows.h>

#include "../include/WfpControlProtocol.h"

namespace furious::wfp::ipc {

// Policy mutation remains deliberately disabled until policy validation,
// driver health negotiation and transactional filter ownership are complete.
inline DWORD DispatchCommand(uint32_t command) noexcept {
    switch (command) {
    case FURIOUS_WFP_IPC_COMMAND_STATUS:
        return ERROR_SUCCESS;
    case FURIOUS_WFP_IPC_COMMAND_SET_POLICY:
    case FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY:
        return ERROR_NOT_SUPPORTED;
    default:
        return ERROR_INVALID_FUNCTION;
    }
}

} // namespace furious::wfp::ipc
