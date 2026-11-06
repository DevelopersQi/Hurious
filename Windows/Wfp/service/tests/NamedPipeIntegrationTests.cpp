#include "../WfpPipeServer.h"
#include "../WfpIpcDispatcher.h"
#include "../../include/WfpControlProtocol.h"
#include "../../include/ApplicationRoutingPolicy.h"

#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace {
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\FuriousWfpService.v1";

int Fail(const char* message, HANDLE stopEvent, furious::wfp::PipeServer& server,
         std::thread& worker) {
    std::fprintf(stderr, "%s (error=%lu)\\n", message, GetLastError());
    SetEvent(stopEvent);
    server.Stop();
    if (worker.joinable()) worker.join();
    CloseHandle(stopEvent);
    return 1;
}

bool Exchange(const void* requestBytes, DWORD requestSize,
              FURIOUS_WFP_IPC_RESPONSE* response) {
    HANDLE client = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 200; ++attempt) {
        client = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (client != INVALID_HANDLE_VALUE) break;
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY) return false;
        WaitNamedPipeW(kPipeName, 25);
        Sleep(10);
    }
    if (client == INVALID_HANDLE_VALUE) {
        SetLastError(ERROR_TIMEOUT);
        return false;
    }
    DWORD transferred = 0;
    if (!WriteFile(client, requestBytes, requestSize, &transferred, nullptr) ||
        transferred != requestSize) {
        const DWORD error = GetLastError();
        CloseHandle(client);
        SetLastError(error);
        return false;
    }
    if (!ReadFile(client, response, sizeof(*response), &transferred, nullptr) ||
        transferred != sizeof(*response)) {
        const DWORD error = GetLastError();
        CloseHandle(client);
        SetLastError(error);
        return false;
    }
    CloseHandle(client);
    return true;
}

std::vector<uint8_t> MakeRequest(uint32_t command, uint64_t requestId,
                                 const void* payload = nullptr, size_t payloadSize = 0) {
    std::vector<uint8_t> bytes(sizeof(FURIOUS_WFP_IPC_HEADER) + payloadSize);
    FURIOUS_WFP_IPC_HEADER header = {};
    header.Magic = FURIOUS_WFP_IPC_MAGIC;
    header.Version = FURIOUS_WFP_IPC_VERSION;
    header.HeaderSize = sizeof(header);
    header.TotalSize = static_cast<uint32_t>(bytes.size());
    header.Command = command;
    header.RequestId = requestId;
    std::memcpy(bytes.data(), &header, sizeof(header));
    if (payloadSize != 0) std::memcpy(bytes.data() + sizeof(header), payload, payloadSize);
    return bytes;
}
}

int main() {
    HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (stopEvent == nullptr) {
        std::fprintf(stderr, "CreateEventW failed: %lu\\n", GetLastError());
        return 1;
    }
    furious::wfp::PipeServer server;
    DWORD serverStatus = ERROR_SUCCESS;
    std::thread worker([&]() { serverStatus = server.Run(stopEvent); });

    FURIOUS_WFP_IPC_RESPONSE response = {};
    const auto statusRequest = MakeRequest(FURIOUS_WFP_IPC_COMMAND_STATUS, 0x12345678u);
    if (!Exchange(statusRequest.data(), static_cast<DWORD>(statusRequest.size()), &response) ||
        response.Header.Magic != FURIOUS_WFP_IPC_MAGIC ||
        response.Header.Version != FURIOUS_WFP_IPC_VERSION ||
        response.Header.Command != FURIOUS_WFP_IPC_COMMAND_STATUS ||
        response.Header.RequestId != 0x12345678u ||
        response.Win32Status != ERROR_SUCCESS || response.ServiceState != SERVICE_RUNNING) {
        return Fail("Named-pipe STATUS exchange failed", stopEvent, server, worker);
    }

    FURIOUS_WFP_POLICY_HEADER policyHeader = {};
    policyHeader.Size = sizeof(policyHeader);
    policyHeader.AbiVersion = FURIOUS_WFP_POLICY_ABI_VERSION;
    policyHeader.RuleCount = 1;
    policyHeader.Backend = FuriousWfpBackendXray;
    policyHeader.PolicyGeneration = 7;
    FURIOUS_WFP_APPLICATION_RULE rule = {};
    rule.Size = sizeof(rule);
    rule.Priority = 10;
    rule.Enabled = 1;
    rule.Action = FuriousWfpActionProxy;
    wchar_t currentExecutable[FURIOUS_WFP_MAX_IMAGE_PATH_CHARS] = {};
    const DWORD executableChars = GetModuleFileNameW(
        nullptr, currentExecutable, static_cast<DWORD>(_countof(currentExecutable)));
    if (executableChars == 0 || executableChars >= _countof(currentExecutable)) {
        return Fail("GetModuleFileNameW failed", stopEvent, server, worker);
    }
    rule.ImagePathChars = executableChars;
    std::memcpy(rule.ImagePath, currentExecutable,
                (static_cast<size_t>(executableChars) + 1) * sizeof(wchar_t));
    std::array<uint8_t, sizeof(policyHeader) + sizeof(rule)> payload = {};
    std::memcpy(payload.data(), &policyHeader, sizeof(policyHeader));
    std::memcpy(payload.data() + sizeof(policyHeader), &rule, sizeof(rule));

    const auto setRequest = MakeRequest(FURIOUS_WFP_IPC_COMMAND_SET_POLICY, 0x12345679u,
                                        payload.data(), payload.size());
    response = {};
    if (!Exchange(setRequest.data(), static_cast<DWORD>(setRequest.size()), &response) ||
        response.Win32Status != ERROR_SUCCESS ||
        response.Header.Command != FURIOUS_WFP_IPC_COMMAND_SET_POLICY ||
        response.Header.RequestId != 0x12345679u) {
        return Fail("Named-pipe SET_POLICY exchange failed", stopEvent, server, worker);
    }

    std::vector<uint8_t> snapshot;
    uint64_t generation = 0;
    if (furious::wfp::ipc::CopyPolicySnapshot(snapshot, &generation) != ERROR_SUCCESS ||
        snapshot.size() != payload.size() || generation != 7) {
        return Fail("SET_POLICY did not update the policy snapshot", stopEvent, server, worker);
    }
    std::vector<furious::wfp::policy::CompiledApplicationRule> compiledSnapshot;
    if (furious::wfp::ipc::CopyCompiledPolicySnapshot(compiledSnapshot) != ERROR_SUCCESS ||
        compiledSnapshot.size() != 1 || compiledSnapshot[0].AppId.empty()) {
        return Fail("SET_POLICY did not compile the WFP application ID", stopEvent, server, worker);
    }

    const auto clearRequest = MakeRequest(FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY, 0x1234567Au);
    response = {};
    if (!Exchange(clearRequest.data(), static_cast<DWORD>(clearRequest.size()), &response) ||
        response.Win32Status != ERROR_SUCCESS ||
        response.Header.Command != FURIOUS_WFP_IPC_COMMAND_CLEAR_POLICY ||
        response.Header.RequestId != 0x1234567Au) {
        return Fail("Named-pipe CLEAR_POLICY exchange failed", stopEvent, server, worker);
    }
    if (furious::wfp::ipc::CopyPolicySnapshot(snapshot, &generation) != ERROR_SUCCESS ||
        !snapshot.empty() || generation != 7) {
        return Fail("CLEAR_POLICY did not clear the policy snapshot", stopEvent, server, worker);
    }
    if (furious::wfp::ipc::CopyCompiledPolicySnapshot(compiledSnapshot) != ERROR_SUCCESS ||
        !compiledSnapshot.empty()) {
        return Fail("CLEAR_POLICY did not clear compiled application IDs", stopEvent, server, worker);
    }

    SetEvent(stopEvent);
    server.Stop();
    worker.join();
    CloseHandle(stopEvent);
    if (serverStatus != ERROR_SUCCESS) {
        std::fprintf(stderr, "Pipe server exited with %lu\\n", serverStatus);
        return 1;
    }
    return 0;
}
