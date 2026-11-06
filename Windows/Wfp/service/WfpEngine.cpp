#include "WfpEngine.h"

#include <fwpmu.h>

#include <cstring>
#include <cwchar>

namespace {

// Stable identifiers owned by Furious. Do not change after deployment;
// changing these GUIDs would orphan previously installed WFP objects.
const GUID kProviderKey =
{ 0x7c0f8c31, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x01 } };

const GUID kSublayerKey =
{ 0x7c0f8c32, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x02 } };

bool IsExpectedText(const wchar_t* actual, const wchar_t* expected) {
    return actual != nullptr && std::wcscmp(actual, expected) == 0;
}

bool IsOwnedProvider(const FWPM_PROVIDER0* provider) {
    return provider != nullptr &&
        (provider->flags & FWPM_PROVIDER_FLAG_PERSISTENT) != 0 &&
        IsExpectedText(provider->displayData.name, L"Furious") &&
        IsExpectedText(provider->displayData.description,
                       L"Furious application traffic routing");
}

bool IsOwnedSublayer(const FWPM_SUBLAYER0* sublayer) {
    return sublayer != nullptr &&
        sublayer->providerKey != nullptr &&
        std::memcmp(sublayer->providerKey, &kProviderKey, sizeof(kProviderKey)) == 0 &&
        (sublayer->flags & FWPM_SUBLAYER_FLAG_PERSISTENT) != 0 &&
        IsExpectedText(sublayer->displayData.name, L"Furious application routing") &&
        IsExpectedText(sublayer->displayData.description,
                       L"Furious-owned application routing filters");
}

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
        FWPM_PROVIDER0* existingProvider = nullptr;
        status = FwpmProviderGetByKey0(handle_, &kProviderKey, &existingProvider);
        if (status == ERROR_SUCCESS) {
            // A matching GUID is not sufficient: refuse to adopt an object
            // that does not have the persistence contract expected by Furious.
            if (!IsOwnedProvider(existingProvider)) {
                status = ERROR_INVALID_DATA;
            }
            if (existingProvider != nullptr) {
                FwpmFreeMemory0(reinterpret_cast<void**>(&existingProvider));
            }
        }
    }

    if (status == ERROR_SUCCESS) {
        FWPM_SUBLAYER0 sublayer = {};
        sublayer.subLayerKey = kSublayerKey;
        sublayer.displayData.name = const_cast<wchar_t*>(L"Furious application routing");
        sublayer.displayData.description =
            const_cast<wchar_t*>(L"Furious-owned application routing filters");
        sublayer.providerKey = const_cast<GUID*>(&kProviderKey);
        sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        sublayer.weight = 0x7FFF;

        status = FwpmSubLayerAdd0(handle_, &sublayer, nullptr);
        if (status == FWP_E_ALREADY_EXISTS) {
            FWPM_SUBLAYER0* existingSublayer = nullptr;
            status = FwpmSubLayerGetByKey0(handle_, &kSublayerKey, &existingSublayer);
            if (status == ERROR_SUCCESS) {
                if (!IsOwnedSublayer(existingSublayer)) {
                    status = ERROR_INVALID_DATA;
                }
                if (existingSublayer != nullptr) {
                    FwpmFreeMemory0(reinterpret_cast<void**>(&existingSublayer));
                }
            }
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

    // Verify both objects before deleting either one. A GUID collision or a
    // partially-created foreign object must never cause us to remove another
    // product's WFP configuration.
    FWPM_SUBLAYER0* existingSublayer = nullptr;
    status = FwpmSubLayerGetByKey0(handle_, &kSublayerKey, &existingSublayer);
    if (status == FWP_E_SUBLAYER_NOT_FOUND) {
        status = ERROR_SUCCESS;
    } else if (status == ERROR_SUCCESS && !IsOwnedSublayer(existingSublayer)) {
        status = ERROR_INVALID_DATA;
    }
    if (existingSublayer != nullptr) {
        FwpmFreeMemory0(reinterpret_cast<void**>(&existingSublayer));
    }

    FWPM_PROVIDER0* existingProvider = nullptr;
    if (status == ERROR_SUCCESS) {
        status = FwpmProviderGetByKey0(handle_, &kProviderKey, &existingProvider);
        if (status == FWP_E_PROVIDER_NOT_FOUND) {
            status = ERROR_SUCCESS;
        } else if (status == ERROR_SUCCESS && !IsOwnedProvider(existingProvider)) {
            status = ERROR_INVALID_DATA;
        }
    }
    if (existingProvider != nullptr) {
        FwpmFreeMemory0(reinterpret_cast<void**>(&existingProvider));
    }

    if (status == ERROR_SUCCESS) {
        const DWORD sublayerStatus = FwpmSubLayerDeleteByKey0(handle_, &kSublayerKey);
        if (sublayerStatus != ERROR_SUCCESS &&
            sublayerStatus != FWP_E_SUBLAYER_NOT_FOUND) {
            status = sublayerStatus;
        }
    }

    if (status == ERROR_SUCCESS) {
        const DWORD providerStatus = FwpmProviderDeleteByKey0(handle_, &kProviderKey);
        if (providerStatus != ERROR_SUCCESS &&
            providerStatus != FWP_E_PROVIDER_NOT_FOUND) {
            status = providerStatus;
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
