#include <ntddk.h>

// FWPS depends on NDIS 6 buffer-list declarations in ndis.h.
#define NDIS_SUPPORT_NDIS6 1
#pragma warning(push)
#pragma warning(disable:4201)
#include <fwpsk.h>
#pragma warning(pop)
#include <wdmsec.h>
#include <initguid.h>

#include "../include/WfpDriverProtocol.h"
#include "../include/WfpRedirectProtocol.h"

C_ASSERT(sizeof(FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG) == 40);
C_ASSERT(sizeof(FURIOUS_WFP_REDIRECT_CONTEXT) == 64);

DEFINE_GUID(
    FURIOUS_WFP_ALE_CONNECT_REDIRECT_V4_CALLOUT,
    0x7c0f8c33, 0x3f1b, 0x4e83,
    0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x03);

DEFINE_GUID(
    FURIOUS_WFP_ALE_CONNECT_REDIRECT_V6_CALLOUT,
    0x7c0f8c35, 0x3f1b, 0x4e83,
    0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x05);

DEFINE_GUID(
    FURIOUS_WFP_PROVIDER_KEY,
    0x7c0f8c31, 0x3f1b, 0x4e83,
    0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x01);

DEFINE_GUID(
    FURIOUS_WFP_DEVICE_CLASS_GUID,
    0x7c0f8c34, 0x3f1b, 0x4e83,
    0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x04);

static const UNICODE_STRING gDeviceName =
    RTL_CONSTANT_STRING(L"\\Device\\FuriousWfpCallout");
static const UNICODE_STRING gSymbolicLink =
    RTL_CONSTANT_STRING(L"\\DosDevices\\FuriousWfpCallout");
static const UNICODE_STRING gDeviceSddl =
    RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

#define FURIOUS_WFP_CALLOUT_COUNT 2

static BOOLEAN gCalloutsRegistered[FURIOUS_WFP_CALLOUT_COUNT] = { FALSE, FALSE };
static BOOLEAN gSymbolicLinkCreated = FALSE;
static UINT32 gCalloutIds[FURIOUS_WFP_CALLOUT_COUNT] = { 0, 0 };
static HANDLE gRedirectHandle = NULL;
static PDEVICE_OBJECT gDeviceObject = NULL;

static NTSTATUS NTAPI FuriousCreateClose(
    PDEVICE_OBJECT deviceObject,
    PIRP irp)
{
    UNREFERENCED_PARAMETER(deviceObject);
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI FuriousDeviceControl(
    PDEVICE_OBJECT deviceObject,
    PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    UNREFERENCED_PARAMETER(deviceObject);
    if (stack->Parameters.DeviceIoControl.IoControlCode ==
            FURIOUS_WFP_DRIVER_IOCTL_QUERY_STATUS &&
        stack->Parameters.DeviceIoControl.InputBufferLength == 0 &&
        stack->Parameters.DeviceIoControl.OutputBufferLength >=
            sizeof(FURIOUS_WFP_DRIVER_STATUS) &&
        irp->AssociatedIrp.SystemBuffer != NULL) {
        FURIOUS_WFP_DRIVER_STATUS* output =
            (FURIOUS_WFP_DRIVER_STATUS*)irp->AssociatedIrp.SystemBuffer;
        RtlZeroMemory(output, sizeof(*output));
        output->Size = sizeof(*output);
        output->Version = FURIOUS_WFP_DRIVER_ABI_VERSION;
        output->Flags = (gCalloutsRegistered[0] && gCalloutsRegistered[1])
            ? FURIOUS_WFP_DRIVER_FLAG_CALLOUT_REGISTERED : 0;
        status = STATUS_SUCCESS;
        information = sizeof(*output);
    } else if (stack->Parameters.DeviceIoControl.IoControlCode ==
                   FURIOUS_WFP_DRIVER_IOCTL_QUERY_STATUS) {
        status = STATUS_BUFFER_TOO_SMALL;
    }

    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

static VOID NTAPI FuriousClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    VOID* layerData,
    const VOID* classifyContext,
    const FWPS_FILTER1* filter,
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
    const FWPS_FILTER1* filter)
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
    {
        ULONG index;
        for (index = 0; index < FURIOUS_WFP_CALLOUT_COUNT; ++index) {
            if (gCalloutsRegistered[index]) {
                NTSTATUS status;
                LARGE_INTEGER retryDelay;
                retryDelay.QuadPart = -1000000;
                for (;;) {
                    status = FwpsCalloutUnregisterById0(gCalloutIds[index]);
                    if (status == STATUS_SUCCESS ||
                        status == STATUS_FWP_CALLOUT_NOT_FOUND) {
                        break;
                    }
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "FuriousWfpCallout: unregister retry, status=0x%08X\\n", status);
                    KeDelayExecutionThread(KernelMode, FALSE, &retryDelay);
                }
                gCalloutsRegistered[index] = FALSE;
                gCalloutIds[index] = 0;
            }
        }
    }
    if (gRedirectHandle != NULL) {
        FwpsRedirectHandleDestroy0(gRedirectHandle);
        gRedirectHandle = NULL;
    }

    if (gSymbolicLinkCreated) {
        IoDeleteSymbolicLink((PUNICODE_STRING)&gSymbolicLink);
        gSymbolicLinkCreated = FALSE;
    }
    if (gDeviceObject != NULL) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
    }
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT driverObject,
    _In_ PUNICODE_STRING registryPath)
{
    FWPS_CALLOUT1 callout = { 0 };
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registryPath);

    driverObject->DriverUnload = FuriousUnload;
    driverObject->MajorFunction[IRP_MJ_CREATE] = FuriousCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = FuriousCreateClose;
    driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = FuriousDeviceControl;

    status = IoCreateDeviceSecure(
        driverObject,
        0,
        (PUNICODE_STRING)&gDeviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        (PUNICODE_STRING)&gDeviceSddl,
        &FURIOUS_WFP_DEVICE_CLASS_GUID,
        &gDeviceObject);
    if (!NT_SUCCESS(status)) {
        gDeviceObject = NULL;
        return status;
    }

    status = IoCreateSymbolicLink(
        (PUNICODE_STRING)&gSymbolicLink,
        (PUNICODE_STRING)&gDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
        return status;
    }
    gSymbolicLinkCreated = TRUE;

    status = FwpsRedirectHandleCreate0(
        &FURIOUS_WFP_PROVIDER_KEY, 0, &gRedirectHandle);
    if (!NT_SUCCESS(status)) {
        IoDeleteSymbolicLink((PUNICODE_STRING)&gSymbolicLink);
        gSymbolicLinkCreated = FALSE;
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
        return status;
    }

    callout.classifyFn = FuriousClassify;
    callout.notifyFn = FuriousNotify;
    callout.flowDeleteFn = FuriousFlowDelete;

    callout.calloutKey = FURIOUS_WFP_ALE_CONNECT_REDIRECT_V4_CALLOUT;
    status = FwpsCalloutRegister1(gDeviceObject, &callout, &gCalloutIds[0]);
    if (NT_SUCCESS(status)) {
        gCalloutsRegistered[0] = TRUE;
        callout.calloutKey = FURIOUS_WFP_ALE_CONNECT_REDIRECT_V6_CALLOUT;
        status = FwpsCalloutRegister1(gDeviceObject, &callout, &gCalloutIds[1]);
        if (NT_SUCCESS(status)) {
            gCalloutsRegistered[1] = TRUE;
            gDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
            return STATUS_SUCCESS;
        }
    }

    if (gCalloutsRegistered[0]) {
        FwpsCalloutUnregisterById0(gCalloutIds[0]);
        gCalloutsRegistered[0] = FALSE;
        gCalloutIds[0] = 0;
    }
    if (gRedirectHandle != NULL) {
        FwpsRedirectHandleDestroy0(gRedirectHandle);
        gRedirectHandle = NULL;
    }
    IoDeleteSymbolicLink((PUNICODE_STRING)&gSymbolicLink);
    gSymbolicLinkCreated = FALSE;
    IoDeleteDevice(gDeviceObject);
    gDeviceObject = NULL;
    return status;
}
