#include "../WfpPipeServer.h"
#include "../../include/WfpControlProtocol.h"

#include <windows.h>

#include <cstdio>
#include <thread>

namespace {
constexpr wchar_t kPipeName[] = L"\\\\.\\pipe\\FuriousWfpService.v1";

int Fail(const char* message, HANDLE stopEvent, furious::wfp::PipeServer& server,
         std::thread& worker) {
    std::fprintf(stderr, "%s (error=%lu)\\n", message, GetLastError());
    SetEvent(stopEvent);
    server.Stop();
    if (worker.joinable()) {
        worker.join();
    }
    CloseHandle(stopEvent);
    return 1;
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
    std::thread worker([&]() {
        serverStatus = server.Run(stopEvent);
    });

    HANDLE client = INVALID_HANDLE_VALUE;
    for (unsigned attempt = 0; attempt < 200; ++attempt) {
        client = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (client != INVALID_HANDLE_VALUE) {
            break;
        }
        const DWORD error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PIPE_BUSY) {
            return Fail("CreateFileW could not connect to the local pipe",
                        stopEvent, server, worker);
        }
        WaitNamedPipeW(kPipeName, 25);
        Sleep(10);
    }
    if (client == INVALID_HANDLE_VALUE) {
        return Fail("Timed out waiting for the named-pipe server",
                    stopEvent, server, worker);
    }

    FURIOUS_WFP_IPC_HEADER request = {};
    request.Magic = FURIOUS_WFP_IPC_MAGIC;
    request.Version = FURIOUS_WFP_IPC_VERSION;
    request.HeaderSize = sizeof(request);
    request.TotalSize = sizeof(request);
    request.Command = FURIOUS_WFP_IPC_COMMAND_STATUS;
    request.RequestId = 0x12345678u;

    DWORD transferred = 0;
    if (!WriteFile(client, &request, sizeof(request), &transferred, nullptr) ||
        transferred != sizeof(request)) {
        CloseHandle(client);
        return Fail("Writing the IPC request failed", stopEvent, server, worker);
    }

    FURIOUS_WFP_IPC_RESPONSE response = {};
    if (!ReadFile(client, &response, sizeof(response), &transferred, nullptr) ||
        transferred != sizeof(response)) {
        CloseHandle(client);
        return Fail("Reading the IPC response failed", stopEvent, server, worker);
    }
    CloseHandle(client);

    if (response.Header.Magic != FURIOUS_WFP_IPC_MAGIC ||
        response.Header.Version != FURIOUS_WFP_IPC_VERSION ||
        response.Header.Command != FURIOUS_WFP_IPC_COMMAND_STATUS ||
        response.Header.RequestId != request.RequestId ||
        response.Win32Status != ERROR_SUCCESS ||
        response.ServiceState != SERVICE_RUNNING) {
        return Fail("The named-pipe STATUS response did not match the request",
                    stopEvent, server, worker);
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
