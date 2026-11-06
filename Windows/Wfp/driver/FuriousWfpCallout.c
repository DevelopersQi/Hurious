#include <ntddk.h>
#include <fwpsk.h>
#include <initguid.h>

// Bootstrap milestone: register a pass-through ALE callout only.
// No management filters are installed yet; network traffic remains unchanged.

DEFINE_GUID(
    FURIOUS_WFP_ALE_CONNECT_V4_CALLOUT,
    0x7c0f8c33, 0x3f1b, 0x4e83,
    0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x03);

static BOOLEAN gCalloutRegistered = FALSE;
static UINT32 gCalloutId = 0;

static VOID NTAPI FuriousClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    VOID* layerData,
    const VOID* classifyContext,
    const FWPS_FILTER0* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    UNREFERENCED_PARAMETER(inFixedValues);
    UNREFERENCED_PARAMETER(inMetaValues);
    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (classifyOut != NULL &&
        (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
    }
}

static NTSTATUS NTAPI FuriousNotify(
    FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    const GUID* filterKey,
    const FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
    return STATUS_SUCCESS;
}

static VOID NTAPI FuriousFlowDelete(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowContext)
{
    UNREFERENCED_PARAMETER(layerId);
    UNREFERENCED_PARAMETER(calloutId);
    UNREFERENCED_PARAMETER(flowContext);
}

static VOID FuriousUnload(_In_ PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
    if (gCalloutRegistered) {
        FwpsCalloutUnregisterById0(gCalloutId);
        gCalloutRegistered = FALSE;
        gCalloutId = 0;
    }
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath)
{
    FWPS_CALLOUT0 callout = { 0 };
    NTSTATUS status;

    UNREFERENCED_PARAMETER(registryPath);
    driverObject->DriverUnload = FuriousUnload;

    callout.calloutKey = FURIOUS_WFP_ALE_CONNECT_V4_CALLOUT;
    callout.classifyFn = FuriousClassify;
    callout.notifyFn = FuriousNotify;
    callout.flowDeleteFn = FuriousFlowDelete;

    status = FwpsCalloutRegister0(driverObject, &callout, &gCalloutId);
    if (NT_SUCCESS(status)) {
        gCalloutRegistered = TRUE;
    }
    return status;
}
