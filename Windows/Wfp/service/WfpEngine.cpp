#include "WfpEngine.h"

#include <fwpmu.h>

#include <cstring>
#include <cwchar>
#include <rpc.h>
#include <limits>

namespace {

// Stable identifiers owned by Furious. Do not change after deployment;
// changing these GUIDs would orphan previously installed WFP objects.
const GUID kProviderKey =
{ 0x7c0f8c31, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x01 } };

const GUID kSublayerKey =
{ 0x7c0f8c32, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x02 } };

const GUID kConnectRedirectV4CalloutKey =
{ 0x7c0f8c33, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x03 } };
const GUID kConnectRedirectV6CalloutKey =
{ 0x7c0f8c35, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x05 } };
const GUID kConnectRedirectV4FilterKey =
{ 0x7c0f8c36, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x06 } };
const GUID kConnectRedirectV6FilterKey =
{ 0x7c0f8c37, 0x3f1b, 0x4e83, { 0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x07 } };

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

bool IsOwnedCallout(const FWPM_CALLOUT0* callout, const GUID& key,
                    const GUID& layer) {
    return callout != nullptr &&
        std::memcmp(&callout->calloutKey, &key, sizeof(key)) == 0 &&
        callout->providerKey != nullptr &&
        std::memcmp(callout->providerKey, &kProviderKey, sizeof(kProviderKey)) == 0 &&
        std::memcmp(&callout->applicableLayer, &layer, sizeof(layer)) == 0;
}

bool IsOwnedFilter(const FWPM_FILTER0* filter, const GUID& key,
                   const GUID& calloutKey, const GUID& layer) {
    return filter != nullptr &&
        std::memcmp(&filter->filterKey, &key, sizeof(key)) == 0 &&
        filter->providerKey != nullptr &&
        std::memcmp(filter->providerKey, &kProviderKey, sizeof(kProviderKey)) == 0 &&
        std::memcmp(&filter->layerKey, &layer, sizeof(layer)) == 0 &&
        std::memcmp(&filter->subLayerKey, &kSublayerKey, sizeof(kSublayerKey)) == 0 &&
        filter->action.type == FWP_ACTION_CALLOUT_TERMINATING &&
        std::memcmp(&filter->action.calloutKey, &calloutKey, sizeof(calloutKey)) == 0;
}

DWORD EnsureCallout(HANDLE engine, const GUID& key, const GUID& layer,
                    const wchar_t* name) {
    FWPM_CALLOUT0 callout = {};
    callout.calloutKey = key;
    callout.displayData.name = const_cast<wchar_t*>(name);
    callout.displayData.description =
        const_cast<wchar_t*>(L"Furious WFP connect redirection callout");
    callout.providerKey = const_cast<GUID*>(&kProviderKey);
    callout.applicableLayer = layer;
    callout.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
    DWORD status = FwpmCalloutAdd0(engine, &callout, nullptr, nullptr);
    if (status != FWP_E_ALREADY_EXISTS) {
        return status;
    }

    FWPM_CALLOUT0* existing = nullptr;
    status = FwpmCalloutGetByKey0(engine, &key, &existing);
    if (status == ERROR_SUCCESS && !IsOwnedCallout(existing, key, layer)) {
        status = ERROR_INVALID_DATA;
    }
    if (existing != nullptr) {
        FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
    }
    return status;
}

DWORD DeleteLegacyRedirectFilter(HANDLE engine, const GUID& filterKey, const GUID& calloutKey, const GUID& layer) {
    FWPM_FILTER0* existing = nullptr;
    DWORD status = FwpmFilterGetByKey0(engine, &filterKey, &existing);
    if (status == FWP_E_FILTER_NOT_FOUND) return ERROR_SUCCESS;
    if (status != ERROR_SUCCESS) return status;
    const bool owned = IsOwnedFilter(existing, filterKey, calloutKey, layer);
    FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
    if (!owned) return ERROR_INVALID_DATA;
    status = FwpmFilterDeleteByKey0(engine, &filterKey);
    return status == FWP_E_FILTER_NOT_FOUND ? ERROR_SUCCESS : status;
}

bool IsOwnedApplicationFilter(const FWPM_FILTER0* filter) {
    if (filter == nullptr || filter->providerKey == nullptr ||
        std::memcmp(filter->providerKey, &kProviderKey, sizeof(kProviderKey)) != 0 ||
        std::memcmp(&filter->subLayerKey, &kSublayerKey, sizeof(kSublayerKey)) != 0 ||
        !IsExpectedText(filter->displayData.name, L"Furious application route rule") ||
        filter->numFilterConditions != 2 || filter->filterCondition == nullptr) return false;
    const bool v4 = std::memcmp(&filter->layerKey, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, sizeof(GUID)) == 0;
    const bool v6 = std::memcmp(&filter->layerKey, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, sizeof(GUID)) == 0;
    if (!v4 && !v6) return false;
    const auto& app = filter->filterCondition[0];
    const auto& protocol = filter->filterCondition[1];
    if (std::memcmp(&app.fieldKey, &FWPM_CONDITION_ALE_APP_ID, sizeof(GUID)) != 0 ||
        app.matchType != FWP_MATCH_EQUAL || app.conditionValue.type != FWP_BYTE_BLOB_TYPE ||
        app.conditionValue.byteBlob == nullptr || app.conditionValue.byteBlob->size == 0 ||
        std::memcmp(&protocol.fieldKey, &FWPM_CONDITION_IP_PROTOCOL, sizeof(GUID)) != 0 ||
        protocol.matchType != FWP_MATCH_EQUAL || protocol.conditionValue.type != FWP_UINT8 ||
        (protocol.conditionValue.uint8 != 6 && protocol.conditionValue.uint8 != 17)) return false;
    if (filter->action.type == FWP_ACTION_PERMIT) return true;
    if (filter->action.type != FWP_ACTION_CALLOUT_TERMINATING) return false;
    const GUID& callout = v4 ? kConnectRedirectV4CalloutKey : kConnectRedirectV6CalloutKey;
    return std::memcmp(&filter->action.calloutKey, &callout, sizeof(GUID)) == 0;
}

DWORD DeleteApplicationFilter(HANDLE engine, const GUID& key) {
    FWPM_FILTER0* existing = nullptr;
    DWORD status = FwpmFilterGetByKey0(engine, &key, &existing);
    if (status == FWP_E_FILTER_NOT_FOUND) return ERROR_SUCCESS;
    if (status != ERROR_SUCCESS) return status;
    const bool owned = IsOwnedApplicationFilter(existing);
    FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
    if (!owned) return ERROR_INVALID_DATA;
    status = FwpmFilterDeleteByKey0(engine, &key);
    return status == FWP_E_FILTER_NOT_FOUND ? ERROR_SUCCESS : status;
}

DWORD EnumerateApplicationFilterKeys(HANDLE engine, std::vector<GUID>* output) {
    if (output == nullptr) return ERROR_INVALID_PARAMETER;
    HANDLE enumeration = nullptr;
    DWORD status = FwpmFilterCreateEnumHandle0(engine, nullptr, &enumeration);
    if (status != ERROR_SUCCESS) return status;
    for (;;) {
        FWPM_FILTER0** entries = nullptr;
        UINT32 count = 0;
        status = FwpmFilterEnum0(engine, enumeration, 128, &entries, &count);
        if (status != ERROR_SUCCESS) {
            if (entries != nullptr) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
            break;
        }
        try {
            for (UINT32 index = 0; index < count; ++index) {
                if (IsOwnedApplicationFilter(entries[index])) {
                    output->push_back(entries[index]->filterKey);
                }
            }
        } catch (...) {
            status = ERROR_NOT_ENOUGH_MEMORY;
        }
        if (entries != nullptr) FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
        if (status != ERROR_SUCCESS || count < 128) break;
    }
    const DWORD destroyStatus = FwpmFilterDestroyEnumHandle0(engine, enumeration);
    return status == ERROR_SUCCESS ? destroyStatus : status;
}
DWORD AddApplicationRuleFilter(HANDLE engine,
    const furious::wfp::policy::CompiledApplicationRule& rule,
    const GUID& layer, const GUID& calloutKey, UINT8 protocol, GUID* createdKey) {
    if (createdKey == nullptr || rule.AppId.empty() ||
        rule.AppId.size() > (std::numeric_limits<UINT32>::max)()) return ERROR_INVALID_PARAMETER;
    FWPM_FILTER0 filter = {};
    const RPC_STATUS uuidStatus = UuidCreate(&filter.filterKey);
    if (uuidStatus != RPC_S_OK && uuidStatus != RPC_S_UUID_LOCAL_ONLY) return uuidStatus;
    filter.displayData.name = const_cast<wchar_t*>(L"Furious application route rule");
    filter.displayData.description = const_cast<wchar_t*>(L"Per-application TCP route rule");
    filter.providerKey = const_cast<GUID*>(&kProviderKey);
    filter.layerKey = layer;
    filter.subLayerKey = kSublayerKey;
    // Application rules belong to the dynamic engine session. If the service
    // crashes or loses its engine handle, WFP removes these filters instead
    // of leaving a stale callout action installed without a live broker.
    filter.flags = 0;
    UINT64 weight = 0x100000000ULL - static_cast<UINT64>(rule.Priority);
    filter.weight.type = FWP_UINT64;
    filter.weight.uint64 = &weight;
    filter.rawContext = static_cast<UINT64>(rule.Priority);
    if (rule.Action == FuriousWfpActionProxy) {
        filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.calloutKey = calloutKey;
    } else if (rule.Action == FuriousWfpActionDirect) {
        filter.action.type = FWP_ACTION_PERMIT;
    } else return ERROR_INVALID_DATA;
    FWP_BYTE_BLOB appId = {};
    appId.size = static_cast<UINT32>(rule.AppId.size());
    appId.data = const_cast<UINT8*>(rule.AppId.data());
    FWPM_FILTER_CONDITION0 conditions[2] = {};
    conditions[0].fieldKey = FWPM_CONDITION_ALE_APP_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_BYTE_BLOB_TYPE;
    conditions[0].conditionValue.byteBlob = &appId;
    conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT8;
    conditions[1].conditionValue.uint8 = protocol;
    filter.numFilterConditions = static_cast<UINT32>(_countof(conditions));
    filter.filterCondition = conditions;
    const DWORD status = FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
    if (status == ERROR_SUCCESS) *createdKey = filter.filterKey;
    return status;
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
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;

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

DWORD Engine::InstallRedirectFilters() {
    if (handle_ == nullptr) return ERROR_INVALID_HANDLE;

    // Remove application filters left persistent by older service versions.
    // Current policy filters are dynamic-session objects, but a service
    // upgrade must also reconcile legacy persistent filters before exposing
    // the callout layers again.
    std::vector<GUID> staleApplicationKeys;
    DWORD status = EnumerateApplicationFilterKeys(handle_, &staleApplicationKeys);
    if (status != ERROR_SUCCESS) return status;

    // Commit removal of stale application and legacy catch-all filters
    // separately. If callout registration fails, no stale redirect filter is
    // left behind.
    status = FwpmTransactionBegin0(handle_, 0);
    if (status != ERROR_SUCCESS) return status;
    for (const GUID& key : staleApplicationKeys) {
        status = DeleteApplicationFilter(handle_, key);
        if (status != ERROR_SUCCESS) break;
    }
    if (status == ERROR_SUCCESS) {
        status = DeleteLegacyRedirectFilter(handle_, kConnectRedirectV4FilterKey,
            kConnectRedirectV4CalloutKey, FWPM_LAYER_ALE_CONNECT_REDIRECT_V4);
    }
    if (status == ERROR_SUCCESS) {
        status = DeleteLegacyRedirectFilter(handle_, kConnectRedirectV6FilterKey,
            kConnectRedirectV6CalloutKey, FWPM_LAYER_ALE_CONNECT_REDIRECT_V6);
    }
    status = CommitOrAbort(handle_, status);
    if (status != ERROR_SUCCESS) return status;

    status = FwpmTransactionBegin0(handle_, 0);
    if (status != ERROR_SUCCESS) return status;
    status = EnsureCallout(handle_, kConnectRedirectV4CalloutKey,
        FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, L"Furious IPv4 connect redirect");
    if (status == ERROR_SUCCESS) {
        status = EnsureCallout(handle_, kConnectRedirectV6CalloutKey,
            FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, L"Furious IPv6 connect redirect");
    }
    return CommitOrAbort(handle_, status);
}

DWORD Engine::ApplyApplicationPolicy(
    const std::vector<furious::wfp::policy::CompiledApplicationRule>& rules) {
    if (handle_ == nullptr) return ERROR_INVALID_HANDLE;
    if (rules.size() > FURIOUS_WFP_MAX_RULES) return ERROR_INVALID_PARAMETER;

    std::vector<GUID> existingKeys;
    DWORD status = EnumerateApplicationFilterKeys(handle_, &existingKeys);
    if (status != ERROR_SUCCESS) return status;

    DWORD beginStatus = FwpmTransactionBegin0(handle_, 0);
    if (beginStatus != ERROR_SUCCESS) return beginStatus;
    for (const GUID& key : existingKeys) {
        status = DeleteApplicationFilter(handle_, key);
        if (status != ERROR_SUCCESS) break;
    }
    if (status == ERROR_SUCCESS) {
        status = DeleteLegacyRedirectFilter(handle_, kConnectRedirectV4FilterKey,
            kConnectRedirectV4CalloutKey, FWPM_LAYER_ALE_CONNECT_REDIRECT_V4);
    }
    if (status == ERROR_SUCCESS) {
        status = DeleteLegacyRedirectFilter(handle_, kConnectRedirectV6FilterKey,
            kConnectRedirectV6CalloutKey, FWPM_LAYER_ALE_CONNECT_REDIRECT_V6);
    }

    // Only TCP is enabled until a separate UDP relay is implemented and tested.
    const UINT8 protocols[] = { 6 };
    for (const auto& rule : rules) {
        if (status != ERROR_SUCCESS) break;
        for (const UINT8 protocol : protocols) {
            GUID key = {};
            status = AddApplicationRuleFilter(handle_, rule,
                FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, kConnectRedirectV4CalloutKey,
                protocol, &key);
            if (status != ERROR_SUCCESS) break;
            status = AddApplicationRuleFilter(handle_, rule,
                FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, kConnectRedirectV6CalloutKey,
                protocol, &key);
            if (status != ERROR_SUCCESS) break;
        }
    }

    return CommitOrAbort(handle_, status);
}

DWORD Engine::RemoveRedirectFilters() {
    if (handle_ == nullptr) return ERROR_INVALID_HANDLE;
    std::vector<GUID> applicationKeys;
    DWORD status = EnumerateApplicationFilterKeys(handle_, &applicationKeys);
    if (status != ERROR_SUCCESS) return status;
    status = FwpmTransactionBegin0(handle_, 0);
    if (status != ERROR_SUCCESS) return status;
    for (const GUID& key : applicationKeys) {
        status = DeleteApplicationFilter(handle_, key);
        if (status != ERROR_SUCCESS) break;
    }
    if (status == ERROR_SUCCESS) {
        status = DeleteLegacyRedirectFilter(handle_, kConnectRedirectV4FilterKey,
            kConnectRedirectV4CalloutKey, FWPM_LAYER_ALE_CONNECT_REDIRECT_V4);
    }
    if (status == ERROR_SUCCESS) {
        status = DeleteLegacyRedirectFilter(handle_, kConnectRedirectV6FilterKey,
            kConnectRedirectV6CalloutKey, FWPM_LAYER_ALE_CONNECT_REDIRECT_V6);
    }
    const GUID* calloutKeys[] = { &kConnectRedirectV4CalloutKey, &kConnectRedirectV6CalloutKey };
    if (status == ERROR_SUCCESS) {
        for (const GUID* key : calloutKeys) {
            FWPM_CALLOUT0* existing = nullptr;
            DWORD current = FwpmCalloutGetByKey0(handle_, key, &existing);
            if (current == FWP_E_CALLOUT_NOT_FOUND) current = ERROR_SUCCESS;
            else if (current == ERROR_SUCCESS) {
                const bool isV4 = std::memcmp(key, &kConnectRedirectV4CalloutKey, sizeof(GUID)) == 0;
                const GUID& layer = isV4 ? FWPM_LAYER_ALE_CONNECT_REDIRECT_V4
                                         : FWPM_LAYER_ALE_CONNECT_REDIRECT_V6;
                if (!IsOwnedCallout(existing, *key, layer)) current = ERROR_INVALID_DATA;
            }
            if (existing != nullptr) FwpmFreeMemory0(reinterpret_cast<void**>(&existing));
            if (current == ERROR_SUCCESS) {
                current = FwpmCalloutDeleteByKey0(handle_, key);
                if (current == FWP_E_CALLOUT_NOT_FOUND) current = ERROR_SUCCESS;
            }
            if (current != ERROR_SUCCESS) { status = current; break; }
        }
    }
    status = CommitOrAbort(handle_, status);
    return status;
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
