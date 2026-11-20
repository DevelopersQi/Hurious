#pragma once
#include <ntddk.h>
#include "../include/WfpDriverProtocol.h"
#include "../include/WfpDatagramProtocol.h"

NTSTATUS FuriousWfpDatagramQueueInitialize(VOID);
VOID FuriousWfpDatagramQueueCleanup(VOID);
VOID FuriousWfpDatagramQueueCancelFile(PFILE_OBJECT FileObject);
BOOLEAN FuriousWfpDatagramQueueIsReady(VOID);
BOOLEAN FuriousWfpDatagramQueueDispatch(PIRP Irp, PIO_STACK_LOCATION Stack);
BOOLEAN FuriousWfpDatagramQueuePushCaptured(
    const FURIOUS_WFP_DATAGRAM_MESSAGE* Message, ULONG MessageBytes);
