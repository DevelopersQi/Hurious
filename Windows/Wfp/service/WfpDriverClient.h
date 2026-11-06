#pragma once

#include <windows.h>

#include "../include/WfpDriverProtocol.h"
#include "../include/WfpRedirectProtocol.h"

namespace furious::wfp::driver {

inline bool IsValidStatus(const FURIOUS_WFP_DRIVER_STATUS& status) noexcept {
    return status.Size == sizeof(FURIOUS_WFP_DRIVER_STATUS) &&
        status.Version == FURIOUS_WFP_DRIVER_ABI_VERSION &&
        status.Reserved == 0 &&
        (status.Flags & ~(FURIOUS_WFP_DRIVER_FLAG_CALLOUT_REGISTERED |
         FURIOUS_WFP_DRIVER_FLAG_ENDPOINT_CONFIGURED)) == 0;
}

inline DWORD SetEndpointConfig(
    const FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG& config) noexcept {
    if (!furious::wfp::redirect::IsValidEndpointConfig(config)) {
        return ERROR_INVALID_PARAMETER;
    }

    HANDLE device = CreateFileW(
        L"\\\\.\\FuriousWfpCallout",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    DWORD bytesReturned = 0;
    const BOOL ok = DeviceIoControl(
        device,
        FURIOUS_WFP_DRIVER_IOCTL_SET_ENDPOINT_CONFIG,
        const_cast<FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG*>(&config),
        sizeof(config),
        nullptr,
        0,
        &bytesReturned,
        nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    return error;
}

inline DWORD ClearEndpointConfig() noexcept {
    HANDLE device = CreateFileW(
        L"\\\\.\\FuriousWfpCallout",
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (device == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    DWORD bytesReturned = 0;
    const BOOL ok = DeviceIoControl(
        device,
        FURIOUS_WFP_DRIVER_IOCTL_CLEAR_ENDPOINT_CONFIG,
        nullptr,
        0,
        nullptr,
        0,
        &bytesReturned,
        nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(device);
    return error;
}

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
    if (bytesReturned != sizeof(status) || !IsValidStatus(status)) {
        return ERROR_REVISION_MISMATCH;
    }

    *output = status;
    return ERROR_SUCCESS;
}

} // namespace furious::wfp::driver
