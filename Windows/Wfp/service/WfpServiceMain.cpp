#include "WfpEngine.h"
#include "WfpPipeServer.h"

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
        PublishStatus(SERVICE_STOP_PENDING, NO_ERROR, 10000);
        if (gStopEvent != nullptr) {
            SetEvent(gStopEvent);
        }
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    gStatusHandle = RegisterServiceCtrlHandlerExW(
        L"FuriousWfpService", ControlHandler, nullptr);
    if (gStatusHandle == nullptr) {
        return;
    }

    PublishStatus(SERVICE_START_PENDING, NO_ERROR, 15000);
    gStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (gStopEvent == nullptr) {
        PublishStatus(SERVICE_STOPPED, GetLastError(), 0);
        return;
    }

    furious::wfp::Engine engine;
    DWORD status = engine.Open();
    if (status == ERROR_SUCCESS) {
        status = engine.EnsureProviderAndSublayer();
    }

    furious::wfp::PipeServer pipeServer;
    std::thread pipeThread;
    DWORD pipeStatus = ERROR_SUCCESS;
    if (status == ERROR_SUCCESS) {
        try {
            pipeThread = std::thread([&pipeServer, &pipeStatus]() {
                pipeStatus = pipeServer.Run(gStopEvent);
                if (pipeStatus != ERROR_SUCCESS) {
                    SetEvent(gStopEvent);
                }
            });
        } catch (...) {
            status = ERROR_NOT_ENOUGH_MEMORY;
        }
    }

    if (status != ERROR_SUCCESS) {
        engine.RemoveProviderAndSublayer();
        engine.Close();
        CloseHandle(gStopEvent);
        gStopEvent = nullptr;
        PublishStatus(SERVICE_STOPPED, status, 0);
        return;
    }

    PublishStatus(SERVICE_RUNNING, NO_ERROR, 0);
    WaitForSingleObject(gStopEvent, INFINITE);

    pipeServer.Stop();
    if (pipeThread.joinable()) {
        pipeThread.join();
    }

    const DWORD cleanupStatus = engine.RemoveProviderAndSublayer();
    engine.Close();
    CloseHandle(gStopEvent);
    gStopEvent = nullptr;
    const DWORD finalStatus = cleanupStatus != ERROR_SUCCESS ? cleanupStatus : pipeStatus;
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
