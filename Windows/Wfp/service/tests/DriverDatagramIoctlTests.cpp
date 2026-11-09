#include <windows.h>
#include <cstdio>
#include <vector>
#include <atomic>

#include "../../include/WfpDriverProtocol.h"
#include "../../include/WfpDatagramProtocol.h"

namespace {
constexpr DWORD kSkip = 77;
constexpr DWORD kMaxMessage = static_cast<DWORD>(
    sizeof(FURIOUS_WFP_DATAGRAM_MESSAGE) + FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD);
constexpr unsigned kHandles = 8;
constexpr unsigned kReadsPerHandle = 8;

HANDLE OpenDevice(DWORD access, DWORD flags) {
    return CreateFileW(L"\\\\.\\FuriousWfpCallout", access,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, flags, nullptr);
}

struct PendingRead {
    OVERLAPPED overlapped{};
    std::vector<unsigned char> buffer;
};

struct CancelArgs {
    HANDLE file;
    PendingRead* request;
    DWORD result = ERROR_SUCCESS;
};

DWORD WINAPI CancelOne(LPVOID raw) {
    auto* args = static_cast<CancelArgs*>(raw);
    if (!CancelIoEx(args->file, &args->request->overlapped)) {
        const DWORD error = GetLastError();
        args->result = error == ERROR_NOT_FOUND ? ERROR_SUCCESS : error;
    }
    return args->result;
}
}

int main() {
    HANDLE queryDevice = OpenDevice(GENERIC_READ, FILE_ATTRIBUTE_NORMAL);
    if (queryDevice == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
            error == ERROR_ACCESS_DENIED || error == ERROR_SERVICE_NOT_ACTIVE) {
            std::printf("SKIP: live WFP driver unavailable (%lu).\n", error);
            return static_cast<int>(kSkip);
        }
        std::printf("FAIL: open query handle (%lu).\n", error);
        return 1;
    }

    FURIOUS_WFP_DATAGRAM_QUEUE_STATUS status = {};
    DWORD returned = 0;
    const BOOL queried = DeviceIoControl(queryDevice,
        FURIOUS_WFP_DRIVER_IOCTL_QUERY_DATAGRAM_QUEUE,
        nullptr, 0, &status, sizeof(status), &returned, nullptr);
    const DWORD queryError = queried ? ERROR_SUCCESS : GetLastError();
    CloseHandle(queryDevice);
    if (!queried || returned != sizeof(status) ||
        status.Size != sizeof(status) ||
        status.Version != FURIOUS_WFP_DRIVER_ABI_VERSION) {
        std::printf("FAIL: queue status IOCTL (%lu, bytes=%lu).\n", queryError, returned);
        return 1;
    }

    HANDLE handles[kHandles] = {};
    std::vector<PendingRead> pending[kHandles];
    for (unsigned h = 0; h < kHandles; ++h) {
        handles[h] = OpenDevice(GENERIC_WRITE, FILE_FLAG_OVERLAPPED);
        if (handles[h] == INVALID_HANDLE_VALUE) {
            std::printf("FAIL: open read handle (%lu).\n", GetLastError());
            for (unsigned i = 0; i < h; ++i) CloseHandle(handles[i]);
            return 1;
        }
        pending[h].resize(kReadsPerHandle);
        for (auto& request : pending[h]) {
            request.buffer.resize(kMaxMessage);
            request.overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
            if (!request.overlapped.hEvent) {
                std::printf("FAIL: CreateEvent (%lu).\n", GetLastError());
                return 1;
            }
            DWORD bytes = 0;
            const BOOL started = DeviceIoControl(handles[h],
                FURIOUS_WFP_DRIVER_IOCTL_DEQUEUE_DATAGRAM,
                nullptr, 0, request.buffer.data(),
                static_cast<DWORD>(request.buffer.size()), &bytes,
                &request.overlapped);
            if (started || GetLastError() != ERROR_IO_PENDING) {
                std::printf("FAIL: dequeue was not pending (%lu).\n", GetLastError());
                return 1;
            }
        }
    }

    // Race cancellation from multiple threads against CSQ removal and worker
    // scheduling. The other half is completed by IRP_MJ_CLEANUP on close.
    std::vector<CancelArgs> args;
    std::vector<HANDLE> threads;
    args.reserve(kHandles * (kReadsPerHandle / 2));
    threads.reserve(kHandles * (kReadsPerHandle / 2));
    for (unsigned h = 0; h < kHandles; ++h) {
        for (unsigned i = 0; i < kReadsPerHandle; i += 2) {
            args.push_back({handles[h], &pending[h][i], ERROR_SUCCESS});
            HANDLE thread = CreateThread(nullptr, 0, CancelOne, &args.back(), 0, nullptr);
            if (!thread) {
                std::printf("FAIL: CreateThread (%lu).\n", GetLastError());
                return 1;
            }
            threads.push_back(thread);
        }
    }
    for (HANDLE thread : threads) {
        WaitForSingleObject(thread, INFINITE);
        CloseHandle(thread);
    }
    for (const auto& item : args) {
        if (item.result != ERROR_SUCCESS) {
            std::printf("FAIL: CancelIoEx race (%lu).\n", item.result);
            return 1;
        }
    }

    // Closing each file object must cancel its remaining pending dequeue IRPs.
    for (HANDLE handle : handles) CloseHandle(handle);
    for (unsigned h = 0; h < kHandles; ++h) {
        for (auto& request : pending[h]) {
            if (WaitForSingleObject(request.overlapped.hEvent, 5000) != WAIT_OBJECT_0) {
                std::printf("FAIL: IRP remained pending after cancel/cleanup.\n");
                return 1;
            }
            CloseHandle(request.overlapped.hEvent);
        }
    }

    std::puts("PASS: live kernel queue status, concurrent pending reads, cancellation, and file cleanup.");
    return 0;
}
