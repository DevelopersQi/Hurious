#pragma once

// Stable, pointer-free ABI for the WFP driver <-> elevated service datagram
// transport. All multi-byte integers are little-endian except address and
// port byte arrays, which retain network byte order.
#if defined(FURIOUS_WFP_KERNEL_MODE)
#include <ntdef.h>
typedef UCHAR FURIOUS_WFP_DGRAM_U8;
typedef USHORT FURIOUS_WFP_DGRAM_U16;
typedef ULONG FURIOUS_WFP_DGRAM_U32;
typedef ULONGLONG FURIOUS_WFP_DGRAM_U64;
#else
#include <stdint.h>
typedef uint8_t FURIOUS_WFP_DGRAM_U8;
typedef uint16_t FURIOUS_WFP_DGRAM_U16;
typedef uint32_t FURIOUS_WFP_DGRAM_U32;
typedef uint64_t FURIOUS_WFP_DGRAM_U64;
#endif

#define FURIOUS_WFP_DATAGRAM_ABI_VERSION 1u
#define FURIOUS_WFP_DATAGRAM_MAGIC 0x46574447u /* "FW DG" */
#define FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD 65507u
#define FURIOUS_WFP_DATAGRAM_QUEUE_MAX_ENTRIES 128u
#define FURIOUS_WFP_DATAGRAM_QUEUE_MAX_BYTES (2u * 1024u * 1024u)

#define FURIOUS_WFP_DATAGRAM_MESSAGE_CAPTURED 1u
#define FURIOUS_WFP_DATAGRAM_MESSAGE_BROKER_REPLY 2u

#define FURIOUS_WFP_DATAGRAM_FAMILY_IPV4 4u
#define FURIOUS_WFP_DATAGRAM_FAMILY_IPV6 6u
#define FURIOUS_WFP_DATAGRAM_PROTOCOL_UDP 17u
#define FURIOUS_WFP_DATAGRAM_DIRECTION_OUTBOUND 1u
#define FURIOUS_WFP_DATAGRAM_DIRECTION_INBOUND 2u

#define FURIOUS_WFP_DATAGRAM_FLAG_CHECKSUM_VALID 0x00000001u
#define FURIOUS_WFP_DATAGRAM_KNOWN_FLAGS FURIOUS_WFP_DATAGRAM_FLAG_CHECKSUM_VALID

#pragma pack(push, 1)
typedef struct FURIOUS_WFP_DATAGRAM_MESSAGE {
    FURIOUS_WFP_DGRAM_U32 Magic;
    FURIOUS_WFP_DGRAM_U16 Version;
    FURIOUS_WFP_DGRAM_U16 HeaderSize;
    FURIOUS_WFP_DGRAM_U32 TotalSize;
    FURIOUS_WFP_DGRAM_U32 MessageType;
    FURIOUS_WFP_DGRAM_U64 Sequence;
    FURIOUS_WFP_DGRAM_U64 PolicyGeneration;
    FURIOUS_WFP_DGRAM_U64 FlowId;
    FURIOUS_WFP_DGRAM_U32 ProcessId;
    FURIOUS_WFP_DGRAM_U32 CompartmentId;
    FURIOUS_WFP_DGRAM_U32 InterfaceIndex;
    FURIOUS_WFP_DGRAM_U32 SubInterfaceIndex;
    FURIOUS_WFP_DGRAM_U16 AddressFamily;
    FURIOUS_WFP_DGRAM_U8 Protocol;
    FURIOUS_WFP_DGRAM_U8 Direction;
    FURIOUS_WFP_DGRAM_U8 SourceAddress[16];
    FURIOUS_WFP_DGRAM_U8 DestinationAddress[16];
    FURIOUS_WFP_DGRAM_U8 SourcePortNetworkOrder[2];
    FURIOUS_WFP_DGRAM_U8 DestinationPortNetworkOrder[2];
    FURIOUS_WFP_DGRAM_U32 PayloadSize;
    FURIOUS_WFP_DGRAM_U32 Flags;
    FURIOUS_WFP_DGRAM_U32 Reserved[2];
} FURIOUS_WFP_DATAGRAM_MESSAGE;
#pragma pack(pop)

#define FURIOUS_WFP_DATAGRAM_HEADER_SIZE ((FURIOUS_WFP_DGRAM_U32)sizeof(FURIOUS_WFP_DATAGRAM_MESSAGE))

static __inline int FuriousWfpIsValidDatagramMessage(
    const FURIOUS_WFP_DATAGRAM_MESSAGE* message,
    FURIOUS_WFP_DGRAM_U32 availableBytes)
{
    FURIOUS_WFP_DGRAM_U32 index;
    if (message == 0 || availableBytes < sizeof(*message) ||
        message->Magic != FURIOUS_WFP_DATAGRAM_MAGIC ||
        message->Version != FURIOUS_WFP_DATAGRAM_ABI_VERSION ||
        message->HeaderSize != sizeof(*message) ||
        message->TotalSize < sizeof(*message) ||
        message->TotalSize > availableBytes ||
        message->PayloadSize > FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD ||
        message->TotalSize != sizeof(*message) + message->PayloadSize ||
        (message->MessageType != FURIOUS_WFP_DATAGRAM_MESSAGE_CAPTURED &&
         message->MessageType != FURIOUS_WFP_DATAGRAM_MESSAGE_BROKER_REPLY) ||
        message->Sequence == 0 || message->PolicyGeneration == 0 ||
        message->FlowId == 0 || message->ProcessId == 0 ||
        (message->AddressFamily != FURIOUS_WFP_DATAGRAM_FAMILY_IPV4 &&
         message->AddressFamily != FURIOUS_WFP_DATAGRAM_FAMILY_IPV6) ||
        message->Protocol != FURIOUS_WFP_DATAGRAM_PROTOCOL_UDP ||
        (message->Direction != FURIOUS_WFP_DATAGRAM_DIRECTION_OUTBOUND &&
         message->Direction != FURIOUS_WFP_DATAGRAM_DIRECTION_INBOUND) ||
        (message->Flags & ~FURIOUS_WFP_DATAGRAM_KNOWN_FLAGS) != 0) {
        return 0;
    }
    if (message->AddressFamily == FURIOUS_WFP_DATAGRAM_FAMILY_IPV4) {
        for (index = 4; index < 16; ++index) {
            if (message->SourceAddress[index] != 0 ||
                message->DestinationAddress[index] != 0) {
                return 0;
            }
        }
    }
    if (message->SourcePortNetworkOrder[0] == 0 &&
        message->SourcePortNetworkOrder[1] == 0) {
        return 0;
    }
    if (message->DestinationPortNetworkOrder[0] == 0 &&
        message->DestinationPortNetworkOrder[1] == 0) {
        return 0;
    }
    if (message->Reserved[0] != 0 || message->Reserved[1] != 0) {
        return 0;
    }
    return 1;
}
