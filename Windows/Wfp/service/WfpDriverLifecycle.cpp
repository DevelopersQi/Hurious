#include "WfpDriverLifecycle.h"

#include <winsvc.h>

#include <cwctype>
#include <string>
#include <vector>

namespace {

constexpr wchar_t kDriverServiceName[] = L"FuriousWfpCallout";
constexpr DWORD kDriverStartTimeoutMs = 15000;
constexpr DWORD kDriverStopTimeoutMs = 15000;

std::wstring NormalizePath(const std::wstring& value) {
    std::wstring result = value;
    for (wchar_t& ch : result) {
        if (ch == L'/') {
            ch = L'\\';
        }
        ch = static_cast<wchar_t>(std::towlower(ch));
    }
    while (result.size() > 3 && result.back() == L'\\') {
        result.pop_back();
    }
    return result;
}

DWORD GetAdjacentDriverPath(std::wstring* output) {
    if (output == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    std::vector<wchar_t> modulePath(32768, L'\0');
    const DWORD length = GetModuleFileNameW(
        nullptr, modulePath.data(), static_cast<DWORD>(modulePath.size()));
    if (length == 0) {
        return GetLastError();
    }
    if (length >= modulePath.size()) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    std::wstring path(modulePath.data(), length);
    const size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos) {
        return ERROR_BAD_PATHNAME;
    }
    path.resize(separator + 1);
    path += L"FuriousWfpCallout.sys";

    std::vector<wchar_t> absolutePath(32768, L'\0');
    const DWORD absoluteLength = GetFullPathNameW(
        path.c_str(), static_cast<DWORD>(absolutePath.size()),
        absolutePath.data(), nullptr);
    if (absoluteLength == 0) {
        return GetLastError();
    }
    if (absoluteLength >= absolutePath.size()) {
        return ERROR_INSUFFICIENT_BUFFER;
    }

    const DWORD attributes = GetFileAttributesW(absolutePath.data());
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return GetLastError();
    }
    if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        return ERROR_FILE_NOT_FOUND;
    }

    *output = absolutePath.data();
    return ERROR_SUCCESS;
}

DWORD VerifyDriverImagePath(SC_HANDLE service, const std::wstring& expectedPath) {
    DWORD required = 0;
    QueryServiceConfigW(service, nullptr, 0, &required);
    if (required == 0) {
        const DWORD error = GetLastError();
        if (error != ERROR_INSUFFICIENT_BUFFER) {
            return error;
        }
    }

    std::vector<BYTE> storage(required);
    auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(storage.data());
    if (!QueryServiceConfigW(service, config, required, &required)) {
        return GetLastError();
    }
    if (config->dwServiceType != SERVICE_KERNEL_DRIVER ||
        config->lpBinaryPathName == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring configured(config->lpBinaryPathName);
    if (configured.size() >= 2 && configured.front() == L'"') {
        const size_t closingQuote = configured.find(L'"', 1);
        if (closingQuote == std::wstring::npos ||
            closingQuote != configured.size() - 1) {
            return ERROR_INVALID_DATA;
        }
        configured = configured.substr(1, closingQuote - 1);
    }

    std::vector<wchar_t> absolutePath(32768, L'\0');
    const DWORD length = GetFullPathNameW(
        configured.c_str(), static_cast<DWORD>(absolutePath.size()),
        absolutePath.data(), nullptr);
    if (length == 0) {
        return GetLastError();
    }
    if (length >= absolutePath.size()) {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    return NormalizePath(absolutePath.data()) == NormalizePath(expectedPath)
        ? ERROR_SUCCESS : ERROR_SERVICE_EXISTS;
}

DWORD WaitForDriverState(SC_HANDLE service, DWORD desiredState, DWORD timeoutMs) {
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    for (;;) {
        SERVICE_STATUS_PROCESS status = {};
        DWORD bytesNeeded = 0;
        if (!QueryServiceStatusEx(
                service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status), sizeof(status), &bytesNeeded)) {
            return GetLastError();
        }
        if (status.dwCurrentState == desiredState) {
            return ERROR_SUCCESS;
        }
        if (desiredState == SERVICE_RUNNING &&
            status.dwCurrentState == SERVICE_STOPPED) {
            return status.dwWin32ExitCode != NO_ERROR
                ? status.dwWin32ExitCode : ERROR_SERVICE_NOT_ACTIVE;
        }
        if (GetTickCount64() >= deadline) {
            return ERROR_TIMEOUT;
        }
        Sleep(100);
    }
}

} // namespace

namespace furious::wfp {

DWORD DriverLifecycle::StartAdjacentDriver() {
    if (driverPresent_) {
        return ERROR_SUCCESS;
    }

    std::wstring driverPath;
    DWORD status = GetAdjacentDriverPath(&driverPath);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    SC_HANDLE manager = OpenSCManagerW(
        nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (manager == nullptr) {
        return GetLastError();
    }

    const std::wstring serviceImage = L"\"" + driverPath + L"\"";
    SC_HANDLE service = CreateServiceW(
        manager,
        kDriverServiceName,
        L"Furious WFP Callout Driver",
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START | SERVICE_STOP,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        serviceImage.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr);

    if (service == nullptr) {
        status = GetLastError();
        if (status == ERROR_SERVICE_EXISTS || status == ERROR_DUPLICATE_SERVICE_NAME) {
            service = OpenServiceW(
                manager, kDriverServiceName,
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG |
                SERVICE_START | SERVICE_STOP);
            if (service == nullptr) {
                status = GetLastError();
            } else {
                status = VerifyDriverImagePath(service, driverPath);
            }
        }
    } else {
        status = ERROR_SUCCESS;
    }

    if (status == ERROR_SUCCESS && service != nullptr) {
        if (StartServiceW(service, 0, nullptr)) {
            startedByThisService_ = true;
        } else {
            status = GetLastError();
            if (status == ERROR_SERVICE_ALREADY_RUNNING) {
                status = ERROR_SUCCESS;
            }
        }
    }

    if (status == ERROR_SUCCESS && service != nullptr) {
        status = WaitForDriverState(service, SERVICE_RUNNING, kDriverStartTimeoutMs);
        driverPresent_ = status == ERROR_SUCCESS;
    }

    if (service != nullptr) {
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
    return status;
}

DWORD DriverLifecycle::StopIfStartedByThisService() noexcept {
    if (!startedByThisService_) {
        return ERROR_SUCCESS;
    }

    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager == nullptr) {
        return GetLastError();
    }
    SC_HANDLE service = OpenServiceW(
        manager, kDriverServiceName, SERVICE_QUERY_STATUS | SERVICE_STOP);
    if (service == nullptr) {
        const DWORD error = GetLastError();
        CloseServiceHandle(manager);
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
            startedByThisService_ = false;
            driverPresent_ = false;
            return ERROR_SUCCESS;
        }
        return error;
    }

    SERVICE_STATUS status = {};
    DWORD result = ERROR_SUCCESS;
    if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
        const DWORD error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE) {
            result = error;
        }
    }
    if (result == ERROR_SUCCESS) {
        result = WaitForDriverState(service, SERVICE_STOPPED, kDriverStopTimeoutMs);
    }
    if (result == ERROR_SUCCESS) {
        startedByThisService_ = false;
        driverPresent_ = false;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return result;
}

} // namespace furious::wfp
