#include "WfpPipeServer.h"

#include "WfpIpcDispatcher.h"

#include <sddl.h>

#include <array>
#include <cstring>

namespace {

constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\FuriousWfpService.v1";
constexpr wchar_t kPipeSddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";

bool IsAuthorizedClient(HANDLE pipe) noexcept {
    if (!ImpersonateNamedPipeClient(pipe)) {
        return false;
    }

    bool authorized = false;
    HANDLE token = nullptr;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token)) {
        DWORD required = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &required);
        std::array<BYTE, 1024> storage = {};
        if (required >= sizeof(TOKEN_USER) && required <= storage.size()) {
            if (GetTokenInformation(token, TokenUser, storage.data(),
                                    static_cast<DWORD>(storage.size()), &required)) {
                const auto* user = reinterpret_cast<const TOKEN_USER*>(storage.data());
                SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
                PSID systemSid = nullptr;
                PSID administratorsSid = nullptr;
                const bool systemSidCreated = AllocateAndInitializeSid(
                    &ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID,
                    0, 0, 0, 0, 0, 0, 0, &systemSid) != FALSE;
                const bool adminSidCreated = AllocateAndInitializeSid(
                    &ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                    DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsSid) != FALSE;

                BOOL isAdministrator = FALSE;
                if (adminSidCreated) {
                    CheckTokenMembership(token, administratorsSid, &isAdministrator);
                }
                const bool isSystem = systemSidCreated &&
                    EqualSid(user->User.Sid, systemSid) != FALSE;
                authorized = isSystem || isAdministrator != FALSE;

                if (administratorsSid != nullptr) {
                    FreeSid(administratorsSid);
                }
                if (systemSid != nullptr) {
                    FreeSid(systemSid);
                }
            }
        }
        CloseHandle(token);
    }

    // Always drop impersonation, including token-query and allocation failures.
    if (!RevertToSelf()) {
        authorized = false;
    }
    return authorized;
}

bool ReadRequest(HANDLE pipe, HANDLE stopEvent, void* buffer,
                 DWORD capacity, DWORD* bytesRead) noexcept {
    for (;;) {
        if (WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) {
            return false;
        }

        DWORD count = 0;
        if (ReadFile(pipe, buffer, capacity, &count, nullptr)) {
            *bytesRead = count;
            return count != 0;
        }

        const DWORD error = GetLastError();
        if (error == ERROR_NO_DATA) {
            Sleep(20);
            continue;
        }
        // A message larger than the fixed protocol buffer is rejected.
        return false;
    }
}

DWORD WriteResponse(HANDLE pipe, const FURIOUS_WFP_IPC_RESPONSE& response) noexcept {
    DWORD written = 0;
    if (!WriteFile(pipe, &response, sizeof(response), &written, nullptr)) {
        return GetLastError();
    }
    return written == sizeof(response) ? ERROR_SUCCESS : ERROR_WRITE_FAULT;
}

DWORD ServeClient(HANDLE pipe, HANDLE stopEvent) noexcept {
    std::array<BYTE, FURIOUS_WFP_IPC_MAX_MESSAGE_SIZE> requestBytes = {};
    DWORD requestSize = 0;
    if (!ReadRequest(pipe, stopEvent, requestBytes.data(),
                     static_cast<DWORD>(requestBytes.size()), &requestSize)) {
        return ERROR_INVALID_DATA;
    }

    const auto validation = furious::wfp::ipc::ValidateRequest(
        requestBytes.data(), requestSize);
    if (validation != furious::wfp::ipc::ValidationResult::Valid) {
        return ERROR_INVALID_DATA;
    }

    // Impersonation is meaningful only after the client has sent a message.
    // Authenticate the sender of this exact request before dispatching it.
    if (!IsAuthorizedClient(pipe)) {
        return ERROR_ACCESS_DENIED;
    }

    FURIOUS_WFP_IPC_HEADER request = {};
    std::memcpy(&request, requestBytes.data(), sizeof(request));

    FURIOUS_WFP_IPC_RESPONSE response = {};
    response.Header.Magic = FURIOUS_WFP_IPC_MAGIC;
    response.Header.Version = FURIOUS_WFP_IPC_VERSION;
    response.Header.HeaderSize = sizeof(FURIOUS_WFP_IPC_HEADER);
    response.Header.TotalSize = sizeof(response);
    response.Header.Command = request.Command;
    response.Header.RequestId = request.RequestId;
    const void* payload = requestSize > sizeof(request)
        ? requestBytes.data() + sizeof(request) : nullptr;
    const size_t payloadSize = requestSize - sizeof(request);
    response.Win32Status = furious::wfp::ipc::DispatchCommand(
        request.Command, payload, payloadSize);
    response.ServiceState = SERVICE_RUNNING;

    return WriteResponse(pipe, response);
}

} // namespace

namespace furious::wfp {

DWORD PipeServer::Run(HANDLE stopEvent) noexcept {
    if (stopEvent == nullptr) {
        return ERROR_INVALID_HANDLE;
    }

    stopping_.store(false);
    while (!stopping_.load() && WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0) {
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                kPipeSddl, SDDL_REVISION_1, &descriptor, nullptr)) {
            return GetLastError();
        }

        SECURITY_ATTRIBUTES security = {};
        security.nLength = sizeof(security);
        security.lpSecurityDescriptor = descriptor;
        security.bInheritHandle = FALSE;

        HANDLE pipe = CreateNamedPipeW(
            kPipeName,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT |
                PIPE_REJECT_REMOTE_CLIENTS,
            1,
            sizeof(FURIOUS_WFP_IPC_RESPONSE),
            FURIOUS_WFP_IPC_MAX_MESSAGE_SIZE,
            0,
            &security);
        const DWORD createError = pipe == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
        LocalFree(descriptor);
        if (pipe == INVALID_HANDLE_VALUE) {
            return createError;
        }

        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        const DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();
        if (!connected && connectError != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            if (stopping_.load() || WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0) {
                break;
            }
            return connectError;
        }

        if (!stopping_.load() && WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0) {
            DWORD mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
            if (SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr)) {
                ServeClient(pipe, stopEvent);
            }
        }

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }
    return ERROR_SUCCESS;
}

void PipeServer::Stop() noexcept {
    stopping_.store(true);
    // Connecting once releases a worker blocked in ConnectNamedPipe.
    // The worker may be between its stop check and CreateNamedPipe.
    // Retry briefly so that a just-created listening instance is also released.
    for (unsigned attempt = 0; attempt < 40; ++attempt) {
        HANDLE wake = CreateFileW(
            kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (wake != INVALID_HANDLE_VALUE) {
            CloseHandle(wake);
            return;
        }
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY) {
            return;
        }
        Sleep(25);
    }
}

} // namespace furious::wfp
