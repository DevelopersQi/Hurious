#include "WfpEngine.h"

#include <fwpmu.h>

namespace {

// Stable identifiers owned by Furious. Do not change after deployment;
// changing these GUIDs would orphan previously installed WFP objects.
const GUID kProviderKey =
{ 0x7c0f8c31, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x01 } };

const GUID kSublayerKey =
{ 0x7c0f8c32, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x02 } };

DWORD CommitOrAbort(HANDLE engine, DWORD operationStatus) {
    if (operationStatus == ERROR_SUCCESS) {
        const DWORD commitStatus = FwpmTransactionCommit0(engine);
        if (commitStatus == ERROR_SUCCESS) {
            return ERROR_SUCCESS;
        }
        FwpmTransactionAbort0(engine);
        return commitStatus;
    }

    FwpmTransactionAbort0(engine);
    return operationStatus;
}

} // namespace

namespace furious::wfp {

Engine::~Engine() {
    Close();
}

DWORD Engine::Open() {
    if (handle_ != nullptr) {
        return ERROR_SUCCESS;
    }

    FWPM_SESSION0 session = {};
    session.displayData.name = const_cast<wchar_t*>(L"Furious WFP management session");
    session.displayData.description =
        const_cast<wchar_t*>(L"Owns Furious application-routing filters");

    return FwpmEngineOpen0(
        nullptr,
        RPC_C_AUTHN_WINNT,
        nullptr,
        &session,
        &handle_);
}

DWORD Engine::EnsureProviderAndSublayer() {
    if (handle_ == nullptr) {
        return ERROR_INVALID_HANDLE;
    }

    DWORD status = FwpmTransactionBegin0(handle_, 0);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    FWPM_PROVIDER0 provider = {};
    provider.providerKey = kProviderKey;
    provider.displayData.name = const_cast<wchar_t*>(L"Furious");
    provider.displayData.description =
        const_cast<wchar_t*>(L"Furious application traffic routing");
    provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

    status = FwpmProviderAdd0(handle_, &provider, nullptr);
    if (status == FWP_E_ALREADY_EXISTS) {
        status = ERROR_SUCCESS;
    }

    if (status == ERROR_SUCCESS) {
        FWPM_SUBLAYER0 sublayer = {};
        sublayer.subLayerKey = kSublayerKey;
        sublayer.displayData.name = const_cast<wchar_t*>(L"Furious application routing");
        sublayer.displayData.description =
            const_cast<wchar_t*>(L"Furious-owned application routing filters");
        sublayer.providerKey = const_cast<GUID*>(&kProviderKey);
        sublayer.weight = 0x7FFF;

        status = FwpmSubLayerAdd0(handle_, &sublayer, nullptr);
        if (status == FWP_E_ALREADY_EXISTS) {
            status = ERROR_SUCCESS;
        }
    }

    return CommitOrAbort(handle_, status);
}

DWORD Engine::RemoveProviderAndSublayer() {
    if (handle_ == nullptr) {
        return ERROR_INVALID_HANDLE;
    }

    DWORD status = FwpmTransactionBegin0(handle_, 0);
    if (status != ERROR_SUCCESS) {
        return status;
    }

    // Delete only objects owned by the Furious provider. Provider deletion
    // also removes its associated filters/callouts; never enumerate and
    // delete objects belonging to Windows Firewall or other products.
    status = FwpmProviderDeleteByKey0(handle_, &kProviderKey);
    if (status == FWP_E_PROVIDER_NOT_FOUND) {
        status = ERROR_SUCCESS;
    }

    if (status == ERROR_SUCCESS) {
        const DWORD sublayerStatus = FwpmSubLayerDeleteByKey0(handle_, &kSublayerKey);
        if (sublayerStatus != ERROR_SUCCESS &&
            sublayerStatus != FWP_E_SUBLAYER_NOT_FOUND) {
            status = sublayerStatus;
        }
    }

    return CommitOrAbort(handle_, status);
}

void Engine::Close() noexcept {
    if (handle_ != nullptr) {
        FwpmEngineClose0(handle_);
        handle_ = nullptr;
    }
}

} // namespace furious::wfp
