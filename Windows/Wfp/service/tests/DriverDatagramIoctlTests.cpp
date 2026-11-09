#include <windows.h>
#include <cstdio>
#include <vector>

#include "../include/WfpDriverProtocol.h"
#include "../include/WfpDatagramProtocol.h"

namespace {
constexpr DWORD kSkip = 77;
constexpr DWORD kMaxMessage =
    static_cast<DWORD>(sizeof(FURIOUS_WFP_DATAGRAM_MESSAGE) +
                       FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD);

HANDLE OpenDevice(DWORD access, DWORD flags) {
    return CreateFileW(
        L"\\\\.\\FuriousWfpCallout",
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        flags,
        nullptr);
}
}

int main() {
    HANDLE queryDevice = OpenDevice(GENERIC_READ, FILE_ATTRIBUTE_NORMAL);
    if (queryDevice == INVALID_HANDLE_VALUE) {
        const DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ||
            error == ERROR_ACCESS_DENIED || error == ERROR_SERVICE_NOT_ACTIVE) {
            std::printf("SKIP: WFP callout device is not installed/accessible (%lu).\\n", error);
            return static_cast<int>(kSkip);
        }
        std::printf("FAIL: cannot open WFP device (%lu).\\n", error);
        return 1;
    }

    FURIOUS_WFP_DATAGRAM_QUEUE_STATUS queue = {};
    DWORD returned = 0;
    const BOOL queried = DeviceIoControl(
        queryDevice,
        FURIOUS_WFP_DRIVER_IOCTL_QUERY_DATAGRAM_QUEUE,
        nullptr, 0, &queue, sizeof(queue), &returned, nullptr);
    const DWORD queryError = queried ? ERROR_SUCCESS : GetLastError();
    CloseHandle(queryDevice);
    if (!queried || returned != sizeof(queue) ||
        queue.Size != sizeof(queue) ||
        queue.Version != FURIOUS_WFP_DRIVER_ABI_VERSION) {
        std::printf("FAIL: queue status IOCTL failed (%lu, bytes=%lu).\\n",
                    queryError, returned);
        return 1;
    }

    HANDLE readDevice = OpenDevice(GENERIC_WRITE, FILE_FLAG_OVERLAPPED);
    if (readDevice == INVALID_HANDLE_VALUE) {
        std::printf("FAIL: cannot open device for dequeue (%lu).\\n", GetLastError());
        return 1;
    }

    std::vector<unsigned char> buffer(kMaxMessage);
    OVERLAPPED overlapped = {};
    overlapped.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (overlapped.hEvent == nullptr) {
        std::printf("FAIL: CreateEvent failed (%lu).\\n", GetLastError());
        CloseHandle(readDevice);
        return 1;
    }

    returned = 0;
    const BOOL started = DeviceIoControl(
        readDevice,
        FURIOUS_WFP_DRIVER_IOCTL_DEQUEUE_DATAGRAM,
        nullptr, 0,
        buffer.data(), static_cast<DWORD>(buffer.size()),
        &returned, &overlapped);
    if (started || GetLastError() != ERROR_IO_PENDING) {
        const DWORD error = started ? ERROR_SUCCESS : GetLastError();
        std::printf("FAIL: dequeue did not pend as expected (%lu).\\n", error);
        CloseHandle(overlapped.hEvent);
        CloseHandle(readDevice);
        return 1;
    }

    if (!CancelIoEx(readDevice, &overlapped) && GetLastError() != ERROR_NOT_FOUND) {
        std::printf("FAIL: CancelIoEx failed (%lu).\\n", GetLastError());
        CloseHandle(overlapped.hEvent);
        CloseHandle(readDevice);
        return 1;
    }

    const DWORD wait = WaitForSingleObject(overlapped.hEvent, 5000);
    DWORD bytes = 0;
    const BOOL completed = GetOverlappedResult(readDevice, &overlapped, &bytes, FALSE);
    const DWORD completionError = completed ? ERROR_SUCCESS : GetLastError();
    CloseHandle(overlapped.hEvent);
    CloseHandle(readDevice);

    if (wait != WAIT_OBJECT_0 || completed ||
        completionError != ERROR_OPERATION_ABORTED) {
        std::printf("FAIL: pending dequeue cancellation mismatch (wait=%lu, completed=%d, error=%lu).\\n",
                    wait, completed ? 1 : 0, completionError);
        return 1;
    }

    std::puts("PASS: live kernel queue status and cancel-safe pending dequeue.");
    return 0;
}
