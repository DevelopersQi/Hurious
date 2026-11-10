#include <ntddk.h>
#include <ws2def.h>
#include <ws2ipdef.h>

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
#include "FuriousWfpDatagramQueue.h"

C_ASSERT(sizeof(FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG) == 76);
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
    FURIOUS_WFP_ALE_FLOW_ESTABLISHED_V4_CALLOUT,
    0x7c0f8c38, 0x3f1b, 0x4e83,
    0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x08);

DEFINE_GUID(
    FURIOUS_WFP_ALE_FLOW_ESTABLISHED_V6_CALLOUT,
    0x7c0f8c39, 0x3f1b, 0x4e83,
    0x9d, 0x7a, 0x62, 0x45, 0x11, 0x90, 0x2a, 0x09);

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

#define FURIOUS_WFP_CALLOUT_COUNT 4
#define FURIOUS_WFP_FLOW_CONTEXT_POOL_TAG 'fWwF'
#define FURIOUS_WFP_FLOW_CONTEXT_MAGIC 0x46574643u /* "FWFC" */

typedef struct _FURIOUS_WFP_FLOW_CONTEXT {
    ULONG Magic;
    ULONG Size;
    UINT64 FlowId;
    ULONG ProcessId;
    ULONG Protocol;
    UINT64 PolicyGeneration;
    UINT16 LayerId;
    UINT16 AddressFamily;
    UINT32 Direction;
} FURIOUS_WFP_FLOW_CONTEXT, *PFURIOUS_WFP_FLOW_CONTEXT;

static BOOLEAN gCalloutsRegistered[FURIOUS_WFP_CALLOUT_COUNT] =
    { FALSE, FALSE, FALSE, FALSE };
static BOOLEAN gSymbolicLinkCreated = FALSE;
static UINT32 gCalloutIds[FURIOUS_WFP_CALLOUT_COUNT] = { 0, 0, 0, 0 };
static HANDLE gRedirectHandle = NULL;
static PDEVICE_OBJECT gDeviceObject = NULL;
static KSPIN_LOCK gEndpointConfigLock;
static FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG gEndpointConfig;
static BOOLEAN gEndpointConfigValid = FALSE;
static BOOLEAN gProcessNotifyRegistered = FALSE;

static BOOLEAN FuriousValidateEndpointConfig(
    const FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG* value)
{
    BOOLEAN v4, v6, tcp, udp;

    if (value == NULL ||
        value->Size != sizeof(*value) ||
        value->AbiVersion != FURIOUS_WFP_REDIRECT_ABI_VERSION ||
        value->Backend < 1u || value->Backend > 3u ||
        value->ProxyProcessId == 0 ||
        value->PolicyGeneration == 0 ||
        value->Reserved0 != 0 ||
        value->ExcludedProcessCount > FURIOUS_WFP_MAX_EXCLUDED_PROCESS_IDS ||
        (value->Flags & ~FURIOUS_WFP_REDIRECT_KNOWN_FLAGS) != 0) {
        return FALSE;
    }

    v4 = (value->Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV4) != 0;
    v6 = (value->Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV6) != 0;
    tcp = (value->Flags & FURIOUS_WFP_REDIRECT_FLAG_TCP) != 0;
    udp = (value->Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) != 0;
    if ((!v4 && !v6) || (!tcp && !udp) ||
        ((v4 && tcp) != (value->TcpPortV4 != 0)) ||
        ((v4 && udp) != (value->UdpPortV4 != 0)) ||
        ((v6 && tcp) != (value->TcpPortV6 != 0)) ||
        ((v6 && udp) != (value->UdpPortV6 != 0)) ||
        (!v4 && (value->TcpPortV4 != 0 || value->UdpPortV4 != 0)) ||
        (!v6 && (value->TcpPortV6 != 0 || value->UdpPortV6 != 0)) ||
        (!tcp && (value->TcpPortV4 != 0 || value->TcpPortV6 != 0)) ||
        (!udp && (value->UdpPortV4 != 0 || value->UdpPortV6 != 0))) {
        return FALSE;
    }
    {
        ULONG index;
        for (index = 0; index < FURIOUS_WFP_MAX_EXCLUDED_PROCESS_IDS; ++index) {
            ULONG processId = value->ExcludedProcessIds[index];
            ULONG previous;
            if (index < value->ExcludedProcessCount) {
                if (processId == 0 || processId == value->ProxyProcessId) {
                    return FALSE;
                }
                for (previous = 0; previous < index; ++previous) {
                    if (value->ExcludedProcessIds[previous] == processId) {
                        return FALSE;
                    }
                }
            } else if (processId != 0) {
                return FALSE;
            }
        }
    }
    return TRUE;
}

static VOID FuriousSetCalloutRegistered(ULONG index, BOOLEAN registered, UINT32 calloutId)
{
    KIRQL oldIrql;

    if (index >= FURIOUS_WFP_CALLOUT_COUNT) {
        return;
    }
    KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
    gCalloutsRegistered[index] = registered;
    gCalloutIds[index] = registered ? calloutId : 0;
    KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
}

static BOOLEAN FuriousIsCalloutRegistered(ULONG index)
{
    KIRQL oldIrql;
    BOOLEAN registered;

    if (index >= FURIOUS_WFP_CALLOUT_COUNT) {
        return FALSE;
    }
    KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
    registered = gCalloutsRegistered[index];
    KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
    return registered;
}

static UINT32 FuriousGetCalloutId(ULONG index)
{
    KIRQL oldIrql;
    UINT32 calloutId;

    if (index >= FURIOUS_WFP_CALLOUT_COUNT) {
        return 0;
    }
    KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
    calloutId = gCalloutIds[index];
    KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
    return calloutId;
}

static VOID NTAPI FuriousProcessNotify(
    PEPROCESS process,
    HANDLE processId,
    PPS_CREATE_NOTIFY_INFO createInfo)
{
    KIRQL oldIrql;
    ULONG processIdValue;

    UNREFERENCED_PARAMETER(process);
    if (createInfo != NULL) {
        return;
    }

    processIdValue = (ULONG)(ULONG_PTR)processId;
    KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
    if (gEndpointConfigValid &&
        gEndpointConfig.ProxyProcessId == processIdValue) {
        // The broker runs inside the WFP service process. If that process
        // exits unexpectedly, invalidate its PID before Windows can reuse it
        // for an unrelated process and redirect traffic to the wrong target.
        RtlZeroMemory(&gEndpointConfig, sizeof(gEndpointConfig));
        gEndpointConfigValid = FALSE;
    } else if (gEndpointConfigValid) {
        // Core PIDs are excluded to prevent the proxy from capturing its own
        // outbound sockets. Remove an exited core immediately: otherwise PID
        // reuse could exempt an unrelated process from application routing.
        (void)FuriousWfpRemoveExcludedProcessId(
            &gEndpointConfig, processIdValue);
    }
    KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
}

static ULONG FuriousGetDriverFlags(void)
{
    KIRQL oldIrql;
    ULONG flags = 0;

    KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
    if (gCalloutsRegistered[0] && gCalloutsRegistered[1] &&
        gCalloutsRegistered[2] && gCalloutsRegistered[3]) {
        flags |= FURIOUS_WFP_DRIVER_FLAG_CALLOUT_REGISTERED;
    }
    if (gEndpointConfigValid) {
        flags |= FURIOUS_WFP_DRIVER_FLAG_ENDPOINT_CONFIGURED;
    }
    if (FuriousWfpDatagramQueueIsReady()) {
        flags |= FURIOUS_WFP_DRIVER_FLAG_DATAGRAM_QUEUE_READY;
    }
    KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
    return flags;
}

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

static NTSTATUS NTAPI FuriousCleanup(
    PDEVICE_OBJECT deviceObject,
    PIRP irp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
    UNREFERENCED_PARAMETER(deviceObject);
    // Closing a service handle must not leave its pending dequeue IRPs
    // resident in the global CSQ. The CSQ callback filters by FILE_OBJECT.
    FuriousWfpDatagramQueueCancelFile(stack->FileObject);
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
    if (FuriousWfpDatagramQueueDispatch(irp, stack)) {
        return irp->IoStatus.Status;
    }
    if (stack->Parameters.DeviceIoControl.IoControlCode ==
            FURIOUS_WFP_DRIVER_IOCTL_SET_ENDPOINT_CONFIG) {
        const FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG* input =
            (const FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG*)irp->AssociatedIrp.SystemBuffer;
        KIRQL oldIrql;
        if (input == NULL ||
            stack->Parameters.DeviceIoControl.InputBufferLength != sizeof(*input)) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else if (!FuriousValidateEndpointConfig(input)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
            RtlCopyMemory(&gEndpointConfig, input, sizeof(gEndpointConfig));
            gEndpointConfigValid = TRUE;
            KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
            status = STATUS_SUCCESS;
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode ==
                   FURIOUS_WFP_DRIVER_IOCTL_CLEAR_ENDPOINT_CONFIG) {
        KIRQL oldIrql;
        if (stack->Parameters.DeviceIoControl.InputBufferLength != 0) {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else {
            KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
            RtlZeroMemory(&gEndpointConfig, sizeof(gEndpointConfig));
            gEndpointConfigValid = FALSE;
            KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
            status = STATUS_SUCCESS;
        }
    } else if (stack->Parameters.DeviceIoControl.IoControlCode ==
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
        output->Flags = FuriousGetDriverFlags();
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

#define FURIOUS_WFP_REDIRECT_POOL_TAG 'cWrF'

static FURIOUS_WFP_REDIRECT_CONTEXT* FuriousAllocateRedirectContext(void)
{
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    return (FURIOUS_WFP_REDIRECT_CONTEXT*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(FURIOUS_WFP_REDIRECT_CONTEXT),
        FURIOUS_WFP_REDIRECT_POOL_TAG);
#else
#pragma warning(suppress: 4996)
    return (FURIOUS_WFP_REDIRECT_CONTEXT*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(FURIOUS_WFP_REDIRECT_CONTEXT),
        FURIOUS_WFP_REDIRECT_POOL_TAG);
#endif
}

static VOID FuriousBlock(FWPS_CLASSIFY_OUT0* classifyOut)
{
    if (classifyOut == NULL) return;
    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static VOID FuriousContinue(FWPS_CLASSIFY_OUT0* classifyOut)
{
    if (classifyOut == NULL) return;
    classifyOut->actionType = FWP_ACTION_CONTINUE;
    classifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
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
    FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG endpoint;
    FURIOUS_WFP_REDIRECT_CONTEXT* redirectContext = NULL;
    FWPS_CONNECTION_REDIRECT_STATE redirectState;
    FWPS_CONNECT_REQUEST0* connectRequest = NULL;
    UINT8 protocol;
    UINT16 targetPort;
    UINT16 addressFamily;
    UINT64 classifyHandle = 0;
    NTSTATUS status;
    KIRQL oldIrql;
    BOOLEAN isV4;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(flowContext);

    if (classifyOut == NULL ||
        (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0 ||
        inFixedValues == NULL || inMetaValues == NULL || filter == NULL ||
        classifyContext == NULL || gRedirectHandle == NULL) {
        return;
    }

    // PROCESS_ID is required to enforce the broker self-exclusion. A redirect
    // record handle is optional on the first connection; requiring it here
    // would silently bypass every connection that has not been redirected yet.
    if (!FWPS_IS_METADATA_FIELD_PRESENT(
            inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        FuriousBlock(classifyOut);
        return;
    }

    KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
    if (!gEndpointConfigValid) {
        KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
        FuriousBlock(classifyOut);
        return;
    }
    RtlCopyMemory(&endpoint, &gEndpointConfig, sizeof(endpoint));
    KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);

    if (inMetaValues->processId == endpoint.ProxyProcessId) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    {
        ULONG index;
        for (index = 0; index < endpoint.ExcludedProcessCount; ++index) {
            if (inMetaValues->processId == endpoint.ExcludedProcessIds[index]) {
                classifyOut->actionType = FWP_ACTION_CONTINUE;
                return;
            }
        }
    }

    isV4 = inFixedValues->layerId == FWPS_LAYER_ALE_CONNECT_REDIRECT_V4;
    if (!isV4 && inFixedValues->layerId != FWPS_LAYER_ALE_CONNECT_REDIRECT_V6) {
        FuriousBlock(classifyOut);
        return;
    }

    if (isV4) {
        protocol = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL].value.uint8;
        addressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V4;
    } else {
        protocol = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_PROTOCOL].value.uint8;
        addressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V6;
    }

    if (protocol == FURIOUS_WFP_REDIRECT_PROTOCOL_TCP) {
        if ((endpoint.Flags & FURIOUS_WFP_REDIRECT_FLAG_TCP) == 0) {
            FuriousBlock(classifyOut);
            return;
        }
        targetPort = isV4 ? endpoint.TcpPortV4 : endpoint.TcpPortV6;
    } else if (protocol == FURIOUS_WFP_REDIRECT_PROTOCOL_UDP) {
        if ((endpoint.Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) == 0) {
            FuriousBlock(classifyOut);
            return;
        }
        targetPort = isV4 ? endpoint.UdpPortV4 : endpoint.UdpPortV6;
    } else {
        FuriousBlock(classifyOut);
        return;
    }

    if (targetPort == 0 ||
        (isV4 && (endpoint.Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV4) == 0) ||
        (!isV4 && (endpoint.Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV6) == 0)) {
        FuriousBlock(classifyOut);
        return;
    }

    if (FWPS_IS_METADATA_FIELD_PRESENT(
            inMetaValues, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
        redirectState = FwpsQueryConnectionRedirectState0(
            inMetaValues->redirectRecords, gRedirectHandle, NULL);
    } else {
        // No redirect record means this is an initial, not-yet-proxied
        // connection. There is no prior redirect state to query.
        redirectState = FWPS_CONNECTION_NOT_REDIRECTED;
    }
    if (redirectState != FWPS_CONNECTION_NOT_REDIRECTED) {
        // Never recursively redirect our own connections or replace another
        // inspector's redirect decision in this first implementation.
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    redirectContext = FuriousAllocateRedirectContext();
    if (redirectContext == NULL) {
        FuriousBlock(classifyOut);
        return;
    }
    RtlZeroMemory(redirectContext, sizeof(*redirectContext));
    redirectContext->Magic = FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC;
    redirectContext->Size = sizeof(*redirectContext);
    redirectContext->AbiVersion = FURIOUS_WFP_REDIRECT_ABI_VERSION;
    redirectContext->AddressFamily = addressFamily;
    redirectContext->Protocol = protocol;
    redirectContext->OriginalProcessId = (FURIOUS_WFP_U32)inMetaValues->processId;
    redirectContext->RulePriority = (FURIOUS_WFP_U32)filter->context;
    redirectContext->PolicyGeneration = endpoint.PolicyGeneration;

    status = FwpsAcquireClassifyHandle0((VOID*)classifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(redirectContext, FURIOUS_WFP_REDIRECT_POOL_TAG);
        FuriousBlock(classifyOut);
        return;
    }

    status = FwpsAcquireWritableLayerDataPointer0(
        classifyHandle, filter->filterId, 0, (PVOID*)&connectRequest, classifyOut);
    if (!NT_SUCCESS(status) || connectRequest == NULL) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        ExFreePoolWithTag(redirectContext, FURIOUS_WFP_REDIRECT_POOL_TAG);
        FuriousBlock(classifyOut);
        return;
    }

    if (isV4) {
        SOCKADDR_IN* remote = (SOCKADDR_IN*)&connectRequest->remoteAddressAndPort;
        SOCKADDR_IN* local = (SOCKADDR_IN*)&connectRequest->localAddressAndPort;
        if (remote->sin_family != AF_INET || remote->sin_port == 0) {
            FwpsApplyModifiedLayerData0(classifyHandle, connectRequest, 0);
            FwpsReleaseClassifyHandle0(classifyHandle);
            ExFreePoolWithTag(redirectContext, FURIOUS_WFP_REDIRECT_POOL_TAG);
            FuriousBlock(classifyOut);
            return;
        }
        // Do not capture unspecified, loopback, multicast or class-E/broadcast
        // destinations. These are local-network/control traffic, not safe
        // unicast proxy targets; redirecting them would blackhole UDP flows.
        {
            const ULONG destinationHostOrder =
                RtlUlongByteSwap(remote->sin_addr.S_un.S_addr);
            const UCHAR destinationFirstOctet =
                (UCHAR)(destinationHostOrder >> 24);
            if (destinationFirstOctet == 0 || destinationFirstOctet == 127 ||
                destinationFirstOctet >= 224) {
                FwpsApplyModifiedLayerData0(classifyHandle, connectRequest, 0);
                FwpsReleaseClassifyHandle0(classifyHandle);
                ExFreePoolWithTag(redirectContext, FURIOUS_WFP_REDIRECT_POOL_TAG);
                FuriousContinue(classifyOut);
                return;
            }
        }
        redirectContext->OriginalPortNetworkOrder = remote->sin_port;
        RtlCopyMemory(redirectContext->OriginalAddress,
                      &remote->sin_addr, sizeof(remote->sin_addr));
        if (local->sin_family == AF_INET && local->sin_addr.S_un.S_addr != 0) {
            remote->sin_addr = local->sin_addr;
        } else {
            remote->sin_addr.S_un.S_addr = RtlUlongByteSwap(0x7F000001u);
        }
        remote->sin_port = RtlUshortByteSwap(targetPort);
    } else {
        SOCKADDR_IN6* remote = (SOCKADDR_IN6*)&connectRequest->remoteAddressAndPort;
        SOCKADDR_IN6* local = (SOCKADDR_IN6*)&connectRequest->localAddressAndPort;
        if (remote->sin6_family != AF_INET6 || remote->sin6_port == 0) {
            FwpsApplyModifiedLayerData0(classifyHandle, connectRequest, 0);
            FwpsReleaseClassifyHandle0(classifyHandle);
            ExFreePoolWithTag(redirectContext, FURIOUS_WFP_REDIRECT_POOL_TAG);
            FuriousBlock(classifyOut);
            return;
        }
        // Preserve local, multicast and scope-dependent destinations.
        // The redirect ABI carries the original IPv6 address but not a scope
        // ID, so link-local and multicast traffic cannot be safely proxied.
        {
            const UCHAR* address = remote->sin6_addr.u.Byte;
            IN6_ADDR loopbackAddress = { 0 };
            BOOLEAN isUnroutable = FALSE;
            BOOLEAN isUnspecified = TRUE;
            loopbackAddress.u.Byte[15] = 1;
            for (ULONG addressIndex = 0; addressIndex < 16; ++addressIndex) {
                if (address[addressIndex] != 0) isUnspecified = FALSE;
            }
            if (RtlCompareMemory(address, &loopbackAddress,
                                 sizeof(loopbackAddress)) == sizeof(loopbackAddress) ||
                isUnspecified || address[0] == 0xFF ||
                (address[0] == 0xFE && (address[1] & 0xC0) == 0x80)) {
                isUnroutable = TRUE;
            } else {
                static const UCHAR mappedPrefix[12] = {
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF
                };
                if (RtlCompareMemory(address, mappedPrefix, sizeof(mappedPrefix)) ==
                        sizeof(mappedPrefix) &&
                    (address[12] == 0 || address[12] == 127 || address[12] >= 224)) {
                    isUnroutable = TRUE;
                }
            }
            if (isUnroutable) {
                FwpsApplyModifiedLayerData0(classifyHandle, connectRequest, 0);
                FwpsReleaseClassifyHandle0(classifyHandle);
                ExFreePoolWithTag(redirectContext, FURIOUS_WFP_REDIRECT_POOL_TAG);
                FuriousContinue(classifyOut);
                return;
            }
        }
        redirectContext->OriginalPortNetworkOrder = remote->sin6_port;
        RtlCopyMemory(redirectContext->OriginalAddress,
                      &remote->sin6_addr, sizeof(remote->sin6_addr));
        if (local->sin6_family == AF_INET6) {
            IN6_ADDR unspecifiedAddress = { 0 };
            if (RtlCompareMemory(&local->sin6_addr, &unspecifiedAddress,
                                 sizeof(unspecifiedAddress)) == sizeof(unspecifiedAddress)) {
                RtlZeroMemory(&remote->sin6_addr, sizeof(remote->sin6_addr));
                remote->sin6_addr.u.Byte[15] = 1;
            } else {
                remote->sin6_addr = local->sin6_addr;
                remote->sin6_scope_id = local->sin6_scope_id;
            }
        } else {
            RtlZeroMemory(&remote->sin6_addr, sizeof(remote->sin6_addr));
            remote->sin6_addr.u.Byte[15] = 1;
        }
        remote->sin6_port = RtlUshortByteSwap(targetPort);
    }

    connectRequest->localRedirectTargetPID = endpoint.ProxyProcessId;
    connectRequest->localRedirectHandle = gRedirectHandle;
    connectRequest->localRedirectContext = redirectContext;
    connectRequest->localRedirectContextSize = sizeof(*redirectContext);

    FwpsApplyModifiedLayerData0(classifyHandle, connectRequest, 0);
    FwpsReleaseClassifyHandle0(classifyHandle);
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights |= FWPS_RIGHT_ACTION_WRITE;
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

static PFURIOUS_WFP_FLOW_CONTEXT FuriousAllocateFlowContext(VOID)
{
#if (NTDDI_VERSION >= NTDDI_WIN10_VB)
    return (PFURIOUS_WFP_FLOW_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(FURIOUS_WFP_FLOW_CONTEXT),
        FURIOUS_WFP_FLOW_CONTEXT_POOL_TAG);
#else
#pragma warning(suppress: 4996)
    return (PFURIOUS_WFP_FLOW_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx, sizeof(FURIOUS_WFP_FLOW_CONTEXT),
        FURIOUS_WFP_FLOW_CONTEXT_POOL_TAG);
#endif
}

static VOID NTAPI FuriousFlowEstablishedClassify(
    const FWPS_INCOMING_VALUES0* inFixedValues,
    const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    VOID* layerData,
    const VOID* classifyContext,
    const FWPS_FILTER1* filter,
    UINT64 flowContext,
    FWPS_CLASSIFY_OUT0* classifyOut)
{
    FURIOUS_WFP_REDIRECT_ENDPOINT_CONFIG endpoint;
    PFURIOUS_WFP_FLOW_CONTEXT context;
    UINT16 layerId;
    UINT16 addressFamily;
    UINT32 calloutIndex;
    UINT8 protocol;
    KIRQL oldIrql;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (classifyOut == NULL ||
        (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0 ||
        inFixedValues == NULL || inMetaValues == NULL) {
        return;
    }

    layerId = inFixedValues->layerId;
    if (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4) {
        addressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V4;
        calloutIndex = 2;
        protocol = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_IP_PROTOCOL].value.uint8;
    } else if (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6) {
        addressFamily = FURIOUS_WFP_REDIRECT_FAMILY_V6;
        calloutIndex = 3;
        protocol = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_IP_PROTOCOL].value.uint8;
    } else {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    // FLOW_HANDLE and PROCESS_ID are mandatory for an attributable flow.
    // Missing metadata is a safe observation miss, never a fabricated ID.
    if (!FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_FLOW_HANDLE) ||
        !FWPS_IS_METADATA_FIELD_PRESENT(inMetaValues, FWPS_METADATA_FIELD_PROCESS_ID) ||
        inMetaValues->flowHandle == 0 || inMetaValues->processId == 0 ||
        protocol != FURIOUS_WFP_REDIRECT_PROTOCOL_UDP) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }

    KeAcquireSpinLock(&gEndpointConfigLock, &oldIrql);
    if (!gEndpointConfigValid) {
        KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    RtlCopyMemory(&endpoint, &gEndpointConfig, sizeof(endpoint));
    KeReleaseSpinLock(&gEndpointConfigLock, oldIrql);

    if ((endpoint.Flags & FURIOUS_WFP_REDIRECT_FLAG_UDP) == 0 ||
        (addressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V4 &&
         (endpoint.Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV4) == 0) ||
        (addressFamily == FURIOUS_WFP_REDIRECT_FAMILY_V6 &&
         (endpoint.Flags & FURIOUS_WFP_REDIRECT_FLAG_IPV6) == 0) ||
        inMetaValues->processId == endpoint.ProxyProcessId) {
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    {
        ULONG index;
        for (index = 0; index < endpoint.ExcludedProcessCount; ++index) {
            if (inMetaValues->processId == endpoint.ExcludedProcessIds[index]) {
                classifyOut->actionType = FWP_ACTION_CONTINUE;
                return;
            }
        }
    }

    context = FuriousAllocateFlowContext();
    if (context == NULL) {
        // Flow tracking is observational in this stage. Do not block traffic
        // merely because telemetry/context allocation is under pressure.
        classifyOut->actionType = FWP_ACTION_CONTINUE;
        return;
    }
    RtlZeroMemory(context, sizeof(*context));
    context->Magic = FURIOUS_WFP_FLOW_CONTEXT_MAGIC;
    context->Size = sizeof(*context);
    context->FlowId = inMetaValues->flowHandle;
    context->ProcessId = (ULONG)inMetaValues->processId;
    context->Protocol = protocol;
    context->PolicyGeneration = endpoint.PolicyGeneration;
    context->LayerId = layerId;
    context->AddressFamily = addressFamily;
    if (layerId == FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4) {
        context->Direction = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_FLOW_ESTABLISHED_V4_DIRECTION].value.uint32;
    } else {
        context->Direction = inFixedValues->incomingValue[
            FWPS_FIELD_ALE_FLOW_ESTABLISHED_V6_DIRECTION].value.uint32;
    }

    status = FwpsFlowAssociateContext0(
        inMetaValues->flowHandle, layerId,
        FuriousGetCalloutId(calloutIndex), (UINT64)(ULONG_PTR)context);
    if (status == STATUS_OBJECT_NAME_EXISTS) {
        // Another instance of this callout already owns the flow context.
        // Never remove or overwrite a context we did not create.
        ExFreePoolWithTag(context, FURIOUS_WFP_FLOW_CONTEXT_POOL_TAG);
    } else if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(context, FURIOUS_WFP_FLOW_CONTEXT_POOL_TAG);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
            "FuriousWfpCallout: flow context association failed, status=0x%08X\\n",
            status);
    }
    classifyOut->actionType = FWP_ACTION_CONTINUE;
}

static VOID NTAPI FuriousFlowDelete(
    UINT16 layerId,
    UINT32 calloutId,
    UINT64 flowContext)
{
    PFURIOUS_WFP_FLOW_CONTEXT context =
        (PFURIOUS_WFP_FLOW_CONTEXT)(ULONG_PTR)flowContext;
    UNREFERENCED_PARAMETER(calloutId);

    if (context == NULL ||
        (layerId != FWPS_LAYER_ALE_FLOW_ESTABLISHED_V4 &&
         layerId != FWPS_LAYER_ALE_FLOW_ESTABLISHED_V6)) {
        return;
    }
    if (context->Magic != FURIOUS_WFP_FLOW_CONTEXT_MAGIC ||
        context->Size != sizeof(*context) ||
        context->LayerId != layerId) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "FuriousWfpCallout: invalid flow context during delete\\n");
        return;
    }
    context->Magic = 0;
    ExFreePoolWithTag(context, FURIOUS_WFP_FLOW_CONTEXT_POOL_TAG);
}

static VOID FuriousUnload(_In_ PDRIVER_OBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);
    // Stop process notifications and unregister every WFP callout before
    // tearing down the datagram queue. Classify callbacks may still publish
    // captured datagrams until the callouts are unregistered; draining the
    // queue first would permit a late callback to enqueue after cleanup.
    if (gProcessNotifyRegistered) {
        NTSTATUS status = PsSetCreateProcessNotifyRoutineEx(
            FuriousProcessNotify, TRUE);
        if (status == STATUS_SUCCESS || status == STATUS_INVALID_PARAMETER) {
            gProcessNotifyRegistered = FALSE;
        } else {
            LARGE_INTEGER retryDelay;
            retryDelay.QuadPart = -1000000;
            while (status != STATUS_SUCCESS && status != STATUS_INVALID_PARAMETER) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "FuriousWfpCallout: process notify removal retry, status=0x%08X\\n", status);
                KeDelayExecutionThread(KernelMode, FALSE, &retryDelay);
                status = PsSetCreateProcessNotifyRoutineEx(FuriousProcessNotify, TRUE);
            }
            gProcessNotifyRegistered = FALSE;
        }
    }
    {
        ULONG index;
        for (index = 0; index < FURIOUS_WFP_CALLOUT_COUNT; ++index) {
            if (FuriousIsCalloutRegistered(index)) {
                NTSTATUS status;
                LARGE_INTEGER retryDelay;
                retryDelay.QuadPart = -1000000;
                for (;;) {
                    status = FwpsCalloutUnregisterById0(FuriousGetCalloutId(index));
                    if (status == STATUS_SUCCESS ||
                        status == STATUS_FWP_CALLOUT_NOT_FOUND) {
                        break;
                    }
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "FuriousWfpCallout: unregister retry, status=0x%08X\\n", status);
                    KeDelayExecutionThread(KernelMode, FALSE, &retryDelay);
                }
                FuriousSetCalloutRegistered(index, FALSE, 0);
            }
        }
    }
    // No WFP classify callback can reach the queue after callout unregister.
    // It is now safe to stop the worker, drain pending reads, and free entries.
    FuriousWfpDatagramQueueCleanup();

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
    UINT32 calloutId = 0;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(registryPath);

    KeInitializeSpinLock(&gEndpointConfigLock);
    RtlZeroMemory(&gEndpointConfig, sizeof(gEndpointConfig));
    gEndpointConfigValid = FALSE;

    status = FuriousWfpDatagramQueueInitialize();
    if (!NT_SUCCESS(status)) return status;

    driverObject->DriverUnload = FuriousUnload;
    driverObject->MajorFunction[IRP_MJ_CREATE] = FuriousCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLOSE] = FuriousCreateClose;
    driverObject->MajorFunction[IRP_MJ_CLEANUP] = FuriousCleanup;
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
        FuriousWfpDatagramQueueCleanup();
        return status;
    }

    status = IoCreateSymbolicLink(
        (PUNICODE_STRING)&gSymbolicLink,
        (PUNICODE_STRING)&gDeviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(gDeviceObject);
        gDeviceObject = NULL;
        FuriousWfpDatagramQueueCleanup();
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
        FuriousWfpDatagramQueueCleanup();
        return status;
    }

    callout.classifyFn = FuriousClassify;
    callout.notifyFn = FuriousNotify;
    callout.flowDeleteFn = FuriousFlowDelete;

    callout.calloutKey = FURIOUS_WFP_ALE_CONNECT_REDIRECT_V4_CALLOUT;
    status = FwpsCalloutRegister1(gDeviceObject, &callout, &calloutId);
    if (NT_SUCCESS(status)) {
        FuriousSetCalloutRegistered(0, TRUE, calloutId);
        callout.calloutKey = FURIOUS_WFP_ALE_CONNECT_REDIRECT_V6_CALLOUT;
        calloutId = 0;
        status = FwpsCalloutRegister1(gDeviceObject, &callout, &calloutId);
        if (NT_SUCCESS(status)) {
            FuriousSetCalloutRegistered(1, TRUE, calloutId);

            callout.classifyFn = FuriousFlowEstablishedClassify;
            callout.calloutKey = FURIOUS_WFP_ALE_FLOW_ESTABLISHED_V4_CALLOUT;
            calloutId = 0;
            status = FwpsCalloutRegister1(gDeviceObject, &callout, &calloutId);
            if (NT_SUCCESS(status)) {
                FuriousSetCalloutRegistered(2, TRUE, calloutId);
                callout.calloutKey = FURIOUS_WFP_ALE_FLOW_ESTABLISHED_V6_CALLOUT;
                calloutId = 0;
                status = FwpsCalloutRegister1(gDeviceObject, &callout, &calloutId);
                if (NT_SUCCESS(status)) {
                    FuriousSetCalloutRegistered(3, TRUE, calloutId);
                    status = PsSetCreateProcessNotifyRoutineEx(FuriousProcessNotify, FALSE);
                    if (NT_SUCCESS(status)) {
                        gProcessNotifyRegistered = TRUE;
                        gDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
                        return STATUS_SUCCESS;
                    }
                }
            }
        }
    }

    {
        ULONG index;
        for (index = 0; index < FURIOUS_WFP_CALLOUT_COUNT; ++index) {
            if (FuriousIsCalloutRegistered(index)) {
                FwpsCalloutUnregisterById0(FuriousGetCalloutId(index));
                FuriousSetCalloutRegistered(index, FALSE, 0);
            }
        }
    }
    if (gRedirectHandle != NULL) {
        FwpsRedirectHandleDestroy0(gRedirectHandle);
        gRedirectHandle = NULL;
    }
    IoDeleteSymbolicLink((PUNICODE_STRING)&gSymbolicLink);
    gSymbolicLinkCreated = FALSE;
    IoDeleteDevice(gDeviceObject);
    gDeviceObject = NULL;
    FuriousWfpDatagramQueueCleanup();
    return status;
}
