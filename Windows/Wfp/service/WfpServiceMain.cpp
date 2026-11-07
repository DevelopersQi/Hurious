#include "WfpDriverClient.h"
#include "WfpDriverLifecycle.h"
#include "WfpEngine.h"
#include "WfpPipeServer.h"
#include "WfpIpcDispatcher.h"

#include <windows.h>

#include <thread>

namespace {

SERVICE_STATUS_HANDLE gStatusHandle = nullptr;
SERVICE_STATUS gStatus = {};
HANDLE gStopEvent = nullptr;

void PublishStatus(DWORD state, DWORD win32ExitCode, DWORD waitHint) {
    gStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gStatus.dwCurrentState = state;
    gStatus.dwWin32ExitCode = win32ExitCode;
    gStatus.dwWaitHint = waitHint;
    gStatus.dwControlsAccepted =
        state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    gStatus.dwCheckPoint = state == SERVICE_START_PENDING ? 1 : 0;
    if (gStatusHandle != nullptr) {
        SetServiceStatus(gStatusHandle, &gStatus);
    }
}

DWORD WINAPI ControlHandler(DWORD control, DWORD, LPVOID, LPVOID) {
    if (control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN) {
        PublishStatus(SERVICE_STOP_PENDING, NO_ERROR, 20000);
        if (gStopEvent != nullptr) {
            SetEvent(gStopEvent);
        }
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

DWORD CleanupWfp(
    furious::wfp::Engine& engine,
    furious::wfp::DriverLifecycle& driver,
    bool filtersInstalled,
    bool providerReady) {
    DWORD endpointStatus = ERROR_SUCCESS;
    if (driver.IsPresent()) {
        endpointStatus = furious::wfp::driver::ClearEndpointConfig();
    }

    // If the endpoint cannot be cleared, remove the redirect filters first.
    // Never stop the listener while a live filter may still target it.
    if (endpointStatus != ERROR_SUCCESS && filtersInstalled) {
        const DWORD filterStatus = engine.RemoveRedirectFilters();
        if (filterStatus != ERROR_SUCCESS) {
            return filterStatus;
        }
        filtersInstalled = false;
    }

    // At this point either the endpoint is clear or no redirect filters remain.
    furious::wfp::ipc::GetTcpBrokerServer().Stop();

    if (filtersInstalled) {
        const DWORD filterStatus = engine.RemoveRedirectFilters();
        if (filterStatus != ERROR_SUCCESS) {
            return filterStatus;
        }
    }

    const DWORD driverStatus = driver.StopIfStartedByThisService();
    if (driverStatus != ERROR_SUCCESS) {
        return driverStatus;
    }

    // A driver that was already running before this service started is not
    // ours to unload. Keep its provider registration intact in that case.
    if (providerReady && !driver.IsPresent()) {
        const DWORD providerStatus = engine.RemoveProviderAndSublayer();
        if (providerStatus != ERROR_SUCCESS) {
            return providerStatus;
        }
    }

    return endpointStatus;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    gStatusHandle = RegisterServiceCtrlHandlerExW(
        L"FuriousWfpService", ControlHandler, nullptr);
    if (gStatusHandle == nullptr) {
        return;
    }

    PublishStatus(SERVICE_START_PENDING, NO_ERROR, 30000);
    gStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (gStopEvent == nullptr) {
        PublishStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    furious::wfp::Engine engine;
    furious::wfp::DriverLifecycle driver;
    bool providerReady = false;
    bool filtersInstalled = false;

    DWORD status = engine.Open();
    if (status == ERROR_SUCCESS) {
        status = engine.EnsureProviderAndSublayer();
        providerReady = status == ERROR_SUCCESS;
    }
    if (status == ERROR_SUCCESS) {
        status = driver.StartAdjacentDriver();
    }
    if (status == ERROR_SUCCESS) {
        FURIOUS_WFP_DRIVER_STATUS driverStatus = {};
        status = furious::wfp::driver::QueryStatus(&driverStatus);
        if (status == ERROR_SUCCESS &&
            (driverStatus.Flags & FURIOUS_WFP_DRIVER_FLAG_CALLOUT_REGISTERED) == 0) {
            status = ERROR_INVALID_STATE;
        }
        if (status == ERROR_SUCCESS) {
            // A previous service crash may have left an endpoint configured.
            // Clear it before enabling filters; no traffic is redirected until
            // a live backend endpoint is explicitly configured.
            status = furious::wfp::driver::ClearEndpointConfig();
        }
    }
    if (status == ERROR_SUCCESS) {
        status = engine.InstallRedirectFilters();
        filtersInstalled = status == ERROR_SUCCESS;
    }

    furious::wfp::PipeServer pipeServer;
    std::thread pipeThread;
    DWORD pipeStatus = ERROR_SUCCESS;
    if (status == ERROR_SUCCESS) {
        try {
            pipeThread = std::thread([&pipeServer, &pipeStatus, &engine]() {
                pipeStatus = pipeServer.Run(gStopEvent, &engine);
                if (pipeStatus != ERROR_SUCCESS) {
                    SetEvent(gStopEvent);
                }
            });
        } catch (...) {
            status = ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    if (status != ERROR_SUCCESS) {
        const DWORD cleanupStatus = CleanupWfp(
            engine, driver, filtersInstalled, providerReady);
        engine.Close();
        CloseHandle(gStopEvent);
        gStopEvent = nullptr;
        PublishStatus(SERVICE_STOPPED,
            cleanupStatus != ERROR_SUCCESS ? cleanupStatus : status, 0);
        return;
    }

    PublishStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(gStopEvent, INFINITE);

    pipeServer.Stop();
    if (pipeThread.joinable()) {
        pipeThread.join();
    }

    const DWORD cleanupStatus = CleanupWfp(
        engine, driver, filtersInstalled, providerReady);
    engine.Close();
    CloseHandle(gStopEvent);
    gStopEvent = nullptr;
    const DWORD finalStatus = cleanupStatus != ERROR_SUCCESS
        ? cleanupStatus : pipeStatus;
    PublishStatus(SERVICE_STOPPED, finalStatus, 0);
}

} // namespace

int wmain() {
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(L"FuriousWfpService"), ServiceMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        return static_cast<int>(GetLastError());
    }
    return 0;
}
