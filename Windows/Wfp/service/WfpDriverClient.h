#pragma once

#include <windows.h>

#include "../include/WfpDriverProtocol.h"

namespace furious::wfp::driver {

inline DWORD QueryStatus(FURIOUS_WFP_DRIVER_STATUS* output) noexcept {
    if (output == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    HANDLE device = CreateFileW(
        L"\\\\.\\FuriousWfpCallout",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    FURIOUS_WFP_DRIVER_STATUS status = {};
    DWORD bytesReturned = 0;
    const BOOL ok = DeviceIoControl(
        device,
        FURIOUS_WFP_DRIVER_IOCTL_QUERY_STATUS,
        nullptr,
        0,
        &status,
        sizeof(status),
        &bytesReturned,
        nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    if (!ok) {
        return error;
    }
    if (bytesReturned != sizeof(status) ||
        status.Size != sizeof(status) ||
        status.Version != FURIOUS_WFP_DRIVER_ABI_VERSION ||
        (status.Flags & ~FURIOUS_WFP_DRIVER_FLAG_CALLOUT_REGISTERED) != 0) {
        return ERROR_REVISION_MISMATCH;
    }

    *output = status;
    return ERROR_SUCCESS;
}

} // namespace furious::wfp::driver
