#pragma once

#include <windows.h>
#include <fwpmu.h>
#include "WfpPolicyCompiler.h"
#include <vector>

namespace furious::wfp {

class Engine final {
public:
    Engine() noexcept = default;
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    DWORD Open();
    DWORD EnsureProviderAndSublayer();
    DWORD InstallRedirectFilters();
    DWORD ApplyApplicationPolicy(
        const std::vector<furious::wfp::policy::CompiledApplicationRule>& rules);
    DWORD RemoveRedirectFilters();
    DWORD RemoveProviderAndSublayer();
    void Close() noexcept;

private:
    HANDLE handle_ = nullptr;
};

} // namespace furious::wfp
