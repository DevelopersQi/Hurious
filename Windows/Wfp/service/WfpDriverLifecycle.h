#pragma once

#include <windows.h>

namespace furious::wfp {

class DriverLifecycle final {
public:
    DriverLifecycle() noexcept = default;
    ~DriverLifecycle() = default;

    DriverLifecycle(const DriverLifecycle&) = delete;
    DriverLifecycle& operator=(const DriverLifecycle&) = delete;

    DWORD StartAdjacentDriver();
    DWORD StopIfStartedByThisService() noexcept;
    bool IsPresent() const noexcept { return driverPresent_; }

private:
    bool startedByThisService_ = false;
    bool driverPresent_ = false;
};

} // namespace furious::wfp
