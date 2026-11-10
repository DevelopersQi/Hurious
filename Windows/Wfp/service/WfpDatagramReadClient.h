#pragma once

#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <thread>
#include <vector>

#include "../include/WfpDriverProtocol.h"
#include "../include/WfpDatagramProtocol.h"

namespace furious::wfp::driver {

// Owns one outstanding overlapped DEQUEUE_DATAGRAM request at a time.
// Stop() does not release the OVERLAPPED or its buffer until the request has
// reached a completion state, including ERROR_OPERATION_ABORTED.
class WfpDatagramReadClient final {
public:
    using MessageHandler =
        std::function<void(const FURIOUS_WFP_DATAGRAM_MESSAGE*, std::size_t)>;

    WfpDatagramReadClient() noexcept = default;
    ~WfpDatagramReadClient() { Stop(); }

    WfpDatagramReadClient(const WfpDatagramReadClient&) = delete;
    WfpDatagramReadClient& operator=(const WfpDatagramReadClient&) = delete;

    DWORD Start(MessageHandler handler) noexcept {
        if (!handler) return ERROR_INVALID_PARAMETER;
        if (running_.load(std::memory_order_acquire)) return ERROR_ALREADY_EXISTS;

        HANDLE device = CreateFileW(
            L"\\\\.\\FuriousWfpCallout",
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            nullptr);
        if (device == INVALID_HANDLE_VALUE) return GetLastError();

        HANDLE stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (stopEvent == nullptr) {
            const DWORD error = GetLastError();
            CloseHandle(device);
            return error;
        }

        device_ = device;
        stopEvent_ = stopEvent;
        handler_ = std::move(handler);
        running_.store(true, std::memory_order_release);
        try {
            worker_ = std::thread(&WfpDatagramReadClient::Run, this);
        } catch (...) {
            running_.store(false, std::memory_order_release);
            handler_ = {};
            CloseHandle(stopEvent_);
            CloseHandle(device_);
            stopEvent_ = nullptr;
            device_ = INVALID_HANDLE_VALUE;
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        return ERROR_SUCCESS;
    }

    void Stop() noexcept {
        if (stopEvent_ == nullptr) return;
        SetEvent(stopEvent_);

        // The worker owns the OVERLAPPED and output buffer. Cancellation is
        // requested here, but those objects remain alive until worker_ joins.
        if (device_ != INVALID_HANDLE_VALUE) {
            CancelIoEx(device_, nullptr);
        }
        if (worker_.joinable()) worker_.join();

        handler_ = {};
        CloseHandle(stopEvent_);
        CloseHandle(device_);
        stopEvent_ = nullptr;
        device_ = INVALID_HANDLE_VALUE;
        running_.store(false, std::memory_order_release);
    }

    bool IsRunning() const noexcept {
        return running_.load(std::memory_order_acquire);
    }

private:
    static constexpr std::size_t kBufferSize =
        sizeof(FURIOUS_WFP_DATAGRAM_MESSAGE) +
        FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD;

    void Run() noexcept {
        std::vector<std::uint8_t> buffer;
        try {
            buffer.resize(kBufferSize);
        } catch (...) {
            running_.store(false, std::memory_order_release);
            return;
        }

        HANDLE ioEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (ioEvent == nullptr) {
            running_.store(false, std::memory_order_release);
            return;
        }

        while (WaitForSingleObject(stopEvent_, 0) != WAIT_OBJECT_0) {
            OVERLAPPED overlapped = {};
            overlapped.hEvent = ioEvent;
            ResetEvent(ioEvent);

            DWORD bytesReturned = 0;
            BOOL completed = DeviceIoControl(
                device_,
                FURIOUS_WFP_DRIVER_IOCTL_DEQUEUE_DATAGRAM,
                nullptr,
                0,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &overlapped);

            if (!completed) {
                const DWORD error = GetLastError();
                if (error != ERROR_IO_PENDING) {
                    if (WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0)
                        break;
                    // A disconnected or restarting driver is not a reason to
                    // spin. Stop this reader; its owner can restart it.
                    break;
                }

                HANDLE waits[2] = { stopEvent_, ioEvent };
                const DWORD waitResult = WaitForMultipleObjects(
                    2, waits, FALSE, INFINITE);
                if (waitResult == WAIT_OBJECT_0) {
                    CancelIoEx(device_, &overlapped);
                    // CancelIoEx only requests cancellation. Wait for the
                    // completion notification before stack/buffer teardown.
                    WaitForSingleObject(ioEvent, INFINITE);
                    GetOverlappedResult(device_, &overlapped, &bytesReturned, FALSE);
                    break;
                }
                if (waitResult != WAIT_OBJECT_0 + 1) break;

                if (!GetOverlappedResult(
                        device_, &overlapped, &bytesReturned, FALSE)) {
                    const DWORD completionError = GetLastError();
                    if (completionError == ERROR_OPERATION_ABORTED &&
                        WaitForSingleObject(stopEvent_, 0) == WAIT_OBJECT_0)
                        break;
                    if (completionError == ERROR_DEVICE_NOT_CONNECTED ||
                        completionError == ERROR_INVALID_HANDLE)
                        break;
                    continue;
                }
            }

            if (bytesReturned < sizeof(FURIOUS_WFP_DATAGRAM_MESSAGE) ||
                bytesReturned > buffer.size()) {
                continue;
            }

            const auto* message =
                reinterpret_cast<const FURIOUS_WFP_DATAGRAM_MESSAGE*>(buffer.data());
            if (!FuriousWfpIsValidDatagramMessage(message, bytesReturned) ||
                message->MessageType != FURIOUS_WFP_DATAGRAM_MESSAGE_CAPTURED) {
                continue;
            }

            try {
                handler_(message, bytesReturned);
            } catch (...) {
                // A consumer exception must not unwind through the reader
                // thread or invalidate the outstanding-I/O lifecycle.
            }
        }

        CloseHandle(ioEvent);
        running_.store(false, std::memory_order_release);
    }

    HANDLE device_ = INVALID_HANDLE_VALUE;
    HANDLE stopEvent_ = nullptr;
    MessageHandler handler_;
    std::thread worker_;
    std::atomic<bool> running_{false};
};

} // namespace furious::wfp::driver
