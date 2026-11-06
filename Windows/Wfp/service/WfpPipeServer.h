#pragma once

#include <windows.h>

#include <atomic>

namespace furious::wfp {

class Engine;

class PipeServer final {
public:
    PipeServer() noexcept = default;
    ~PipeServer() = default;

    PipeServer(const PipeServer&) = delete;
    PipeServer& operator=(const PipeServer&) = delete;

    DWORD Run(HANDLE stopEvent, Engine* engine = nullptr) noexcept;
    void Stop() noexcept;

private:
    std::atomic<bool> stopping_{false};
};

} // namespace furious::wfp
