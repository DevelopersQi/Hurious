#include "FuriousWfpDatagramQueue.h"

#define FURIOUS_DGRAM_POOL_TAG 'qDwF'
#define FURIOUS_DGRAM_MAX_MESSAGE (sizeof(FURIOUS_WFP_DATAGRAM_MESSAGE) + FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD)

typedef struct _FURIOUS_DGRAM_ENTRY {
    LIST_ENTRY Link;
    ULONG Size;
    UCHAR Data[1];
} FURIOUS_DGRAM_ENTRY, *PFURIOUS_DGRAM_ENTRY;

static KSPIN_LOCK gQueueLock;
static LIST_ENTRY gCapturedQueue;
static ULONG gCapturedEntries = 0;
static ULONG gCapturedBytes = 0;
static ULONG gDroppedCaptured = 0;
static IO_CSQ gReadCsq;
static LIST_ENTRY gPendingReads;
static KEVENT gWorkEvent;
static HANDLE gWorkerHandle = NULL;
static PETHREAD gWorkerThread = NULL;
static volatile LONG gStopping = 0;
static volatile LONG gReady = 0;

static VOID NTAPI CsqInsertIrp(PIO_CSQ Csq, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    InsertTailList(&gPendingReads, &Irp->Tail.Overlay.ListEntry);
}
static VOID NTAPI CsqRemoveIrp(PIO_CSQ Csq, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}
static PIRP NTAPI CsqPeekNextIrp(PIO_CSQ Csq, PIRP Irp, PVOID PeekContext)
{
    PLIST_ENTRY cursor;
    UNREFERENCED_PARAMETER(Csq);
    cursor = (Irp == NULL) ? gPendingReads.Flink : Irp->Tail.Overlay.ListEntry.Flink;
    while (cursor != &gPendingReads) {
        PIRP candidate = CONTAINING_RECORD(cursor, IRP, Tail.Overlay.ListEntry);
        if (PeekContext == NULL || candidate->Tail.Overlay.DriverContext[0] == PeekContext)
            return candidate;
        cursor = cursor->Flink;
    }
    return NULL;
}
static VOID NTAPI CsqAcquireLock(PIO_CSQ Csq, PKIRQL Irql)
{
    UNREFERENCED_PARAMETER(Csq);
    KeAcquireSpinLock(&gQueueLock, Irql);
}
static VOID NTAPI CsqReleaseLock(PIO_CSQ Csq, KIRQL Irql)
{
    UNREFERENCED_PARAMETER(Csq);
    KeReleaseSpinLock(&gQueueLock, Irql);
}
static VOID NTAPI CsqCompleteCanceledIrp(PIO_CSQ Csq, PIRP Irp)
{
    UNREFERENCED_PARAMETER(Csq);
    Irp->IoStatus.Status = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static PFURIOUS_DGRAM_ENTRY PopCaptured(VOID)
{
    KIRQL irql;
    PFURIOUS_DGRAM_ENTRY entry = NULL;
    KeAcquireSpinLock(&gQueueLock, &irql);
    if (!IsListEmpty(&gCapturedQueue)) {
        PLIST_ENTRY link = RemoveHeadList(&gCapturedQueue);
        entry = CONTAINING_RECORD(link, FURIOUS_DGRAM_ENTRY, Link);
        --gCapturedEntries;
        gCapturedBytes -= entry->Size;
    }
    KeReleaseSpinLock(&gQueueLock, irql);
    return entry;
}

static VOID NTAPI DatagramReadWorker(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    for (;;) {
        KeWaitForSingleObject(&gWorkEvent, Executive, KernelMode, FALSE, NULL);
        if (InterlockedCompareExchange(&gStopping, 0, 0) != 0)
            PsTerminateSystemThread(STATUS_SUCCESS);

        for (;;) {
            PIRP irp = IoCsqRemoveNextIrp(&gReadCsq, NULL);
            PFURIOUS_DGRAM_ENTRY entry;
            if (irp == NULL)
                break;
            entry = PopCaptured();
            if (entry == NULL) {
                // A producer may have raced the dequeue. Requeue the read;
                // the synchronization event remains signaled if data arrived.
                IoCsqInsertIrp(&gReadCsq, irp, NULL);
                break;
            }
            if (irp->AssociatedIrp.SystemBuffer == NULL ||
                IoGetCurrentIrpStackLocation(irp)->Parameters.DeviceIoControl.OutputBufferLength < entry->Size) {
                KIRQL irql;
                KeAcquireSpinLock(&gQueueLock, &irql);
                InsertHeadList(&gCapturedQueue, &entry->Link);
                ++gCapturedEntries;
                gCapturedBytes += entry->Size;
                KeReleaseSpinLock(&gQueueLock, irql);
                irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
                irp->IoStatus.Information = 0;
            } else {
                RtlCopyMemory(irp->AssociatedIrp.SystemBuffer, entry->Data, entry->Size);
                irp->IoStatus.Status = STATUS_SUCCESS;
                irp->IoStatus.Information = entry->Size;
                ExFreePoolWithTag(entry, FURIOUS_DGRAM_POOL_TAG);
            }
            IoCompleteRequest(irp, IO_NO_INCREMENT);
        }
    }
}

NTSTATUS FuriousWfpDatagramQueueInitialize(VOID)
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    KeInitializeSpinLock(&gQueueLock);
    InitializeListHead(&gCapturedQueue);
    InitializeListHead(&gPendingReads);
    KeInitializeEvent(&gWorkEvent, SynchronizationEvent, FALSE);
    gCapturedEntries = gCapturedBytes = gDroppedCaptured = 0;
    InterlockedExchange(&gStopping, 0);
    status = IoCsqInitialize(&gReadCsq, CsqInsertIrp, CsqRemoveIrp,
        CsqPeekNextIrp, CsqAcquireLock, CsqReleaseLock, CsqCompleteCanceledIrp);
    if (!NT_SUCCESS(status))
        return status;
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL,
        NULL, DatagramReadWorker, NULL);
    if (!NT_SUCCESS(status))
        return status;
    status = ObReferenceObjectByHandle(threadHandle, SYNCHRONIZE, *PsThreadType,
        KernelMode, (PVOID*)&gWorkerThread, NULL);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        InterlockedExchange(&gStopping, 1);
        KeSetEvent(&gWorkEvent, IO_NO_INCREMENT, FALSE);
        return status;
    }
    InterlockedExchange(&gReady, 1);
    return STATUS_SUCCESS;
}

VOID FuriousWfpDatagramQueueCleanup(VOID)
{
    PFURIOUS_DGRAM_ENTRY entry;
    PIRP irp;
    if (InterlockedExchange(&gReady, 0) == 0)
        return;
    InterlockedExchange(&gStopping, 1);
    KeSetEvent(&gWorkEvent, IO_NO_INCREMENT, FALSE);
    if (gWorkerThread != NULL) {
        KeWaitForSingleObject(gWorkerThread, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(gWorkerThread);
        gWorkerThread = NULL;
    }
    if (gWorkerHandle != NULL) {
        ZwClose(gWorkerHandle);
        gWorkerHandle = NULL;
    }
    while ((irp = IoCsqRemoveNextIrp(&gReadCsq, NULL)) != NULL) {
        irp->IoStatus.Status = STATUS_DELETE_PENDING;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
    while ((entry = PopCaptured()) != NULL)
        ExFreePoolWithTag(entry, FURIOUS_DGRAM_POOL_TAG);
}

BOOLEAN FuriousWfpDatagramQueueIsReady(VOID)
{
    return InterlockedCompareExchange(&gReady, 0, 0) != 0;
}

BOOLEAN FuriousWfpDatagramQueuePushCaptured(
    const FURIOUS_WFP_DATAGRAM_MESSAGE* Message, ULONG MessageBytes)
{
    PFURIOUS_DGRAM_ENTRY entry;
    KIRQL irql;
    if (!FuriousWfpDatagramQueueIsReady() ||
        !FuriousWfpIsValidDatagramMessage(Message, MessageBytes) ||
        Message->MessageType != FURIOUS_WFP_DATAGRAM_MESSAGE_CAPTURED ||
        MessageBytes > FURIOUS_DGRAM_MAX_MESSAGE)
        return FALSE;
    entry = (PFURIOUS_DGRAM_ENTRY)ExAllocatePoolWithTag(
        NonPagedPoolNx, FIELD_OFFSET(FURIOUS_DGRAM_ENTRY, Data) + MessageBytes,
        FURIOUS_DGRAM_POOL_TAG);
    if (entry == NULL)
        return FALSE;
    entry->Size = MessageBytes;
    RtlCopyMemory(entry->Data, Message, MessageBytes);
    KeAcquireSpinLock(&gQueueLock, &irql);
    if (InterlockedCompareExchange(&gStopping, 0, 0) != 0 ||
        gCapturedEntries >= FURIOUS_WFP_DATAGRAM_QUEUE_MAX_ENTRIES ||
        MessageBytes > FURIOUS_WFP_DATAGRAM_QUEUE_MAX_BYTES - gCapturedBytes) {
        ++gDroppedCaptured;
        KeReleaseSpinLock(&gQueueLock, irql);
        ExFreePoolWithTag(entry, FURIOUS_DGRAM_POOL_TAG);
        return FALSE;
    }
    InsertTailList(&gCapturedQueue, &entry->Link);
    ++gCapturedEntries;
    gCapturedBytes += MessageBytes;
    KeReleaseSpinLock(&gQueueLock, irql);
    KeSetEvent(&gWorkEvent, IO_NO_INCREMENT, FALSE);
    return TRUE;
}

BOOLEAN FuriousWfpDatagramQueueDispatch(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    ULONG code = Stack->Parameters.DeviceIoControl.IoControlCode;
    if (code == FURIOUS_WFP_DRIVER_IOCTL_DEQUEUE_DATAGRAM) {
        if (Stack->Parameters.DeviceIoControl.InputBufferLength != 0 ||
            Stack->Parameters.DeviceIoControl.OutputBufferLength < FURIOUS_DGRAM_MAX_MESSAGE) {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return TRUE;
        }
        if (!FuriousWfpDatagramQueueIsReady()) {
            Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return TRUE;
        }
        Irp->IoStatus.Status = STATUS_PENDING;
        Irp->IoStatus.Information = 0;
        IoMarkIrpPending(Irp);
        IoCsqInsertIrp(&gReadCsq, Irp, NULL);
        KeSetEvent(&gWorkEvent, IO_NO_INCREMENT, FALSE);
        return TRUE;
    }
    if (code == FURIOUS_WFP_DRIVER_IOCTL_QUERY_DATAGRAM_QUEUE) {
        FURIOUS_WFP_DATAGRAM_QUEUE_STATUS* output;
        KIRQL irql;
        if (Stack->Parameters.DeviceIoControl.InputBufferLength != 0 ||
            Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(*output) ||
            Irp->AssociatedIrp.SystemBuffer == NULL) {
            Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = 0;
        } else {
            output = (FURIOUS_WFP_DRIVER_DATAGRAM_QUEUE_STATUS*)Irp->AssociatedIrp.SystemBuffer;
            RtlZeroMemory(output, sizeof(*output));
            KeAcquireSpinLock(&gQueueLock, &irql);
            output->Size = sizeof(*output);
            output->Version = FURIOUS_WFP_DRIVER_ABI_VERSION;
            output->CapturedEntries = gCapturedEntries;
            output->CapturedBytes = gCapturedBytes;
            output->DroppedCaptured = gDroppedCaptured;
            KeReleaseSpinLock(&gQueueLock, irql);
            Irp->IoStatus.Status = STATUS_SUCCESS;
            Irp->IoStatus.Information = sizeof(*output);
        }
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return TRUE;
    }
    if (code == FURIOUS_WFP_DRIVER_IOCTL_ENQUEUE_DATAGRAM_REPLY) {
        // Do not acknowledge replies until the WFP injection/completion path
        // exists. Returning success here would silently discard user data.
        Irp->IoStatus.Status = STATUS_DEVICE_NOT_READY;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return TRUE;
    }
    return FALSE;
}
