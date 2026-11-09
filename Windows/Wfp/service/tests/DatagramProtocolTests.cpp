#include "../include/WfpDatagramProtocol.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#define CHECK(value) do { if (!(value)) { \
    std::fprintf(stderr, "Check failed at line %d: %s\\n", __LINE__, #value); \
    return 1; \
} } while (0)

int main() {
    static_assert(sizeof(FURIOUS_WFP_DATAGRAM_MESSAGE) == 112,
                  "Datagram message ABI size changed");
    static_assert(FURIOUS_WFP_DATAGRAM_QUEUE_MAX_BYTES >=
                  FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD,
                  "Queue must hold at least one maximum-size datagram");

    std::array<std::uint8_t, sizeof(FURIOUS_WFP_DATAGRAM_MESSAGE) +
                              FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD> storage = {};
    auto* message = reinterpret_cast<FURIOUS_WFP_DATAGRAM_MESSAGE*>(storage.data());
    message->Magic = FURIOUS_WFP_DATAGRAM_MAGIC;
    message->Version = FURIOUS_WFP_DATAGRAM_ABI_VERSION;
    message->HeaderSize = sizeof(*message);
    message->PayloadSize = 12;
    message->TotalSize = sizeof(*message) + message->PayloadSize;
    message->MessageType = FURIOUS_WFP_DATAGRAM_MESSAGE_CAPTURED;
    message->Sequence = 1;
    message->PolicyGeneration = 7;
    message->FlowId = 99;
    message->ProcessId = 1234;
    message->AddressFamily = FURIOUS_WFP_DATAGRAM_FAMILY_IPV4;
    message->Protocol = FURIOUS_WFP_DATAGRAM_PROTOCOL_UDP;
    message->Direction = FURIOUS_WFP_DATAGRAM_DIRECTION_OUTBOUND;
    message->SourceAddress[0] = 10;
    message->DestinationAddress[0] = 8;
    message->SourcePortNetworkOrder[0] = 0x1F;
    message->SourcePortNetworkOrder[1] = 0x90;
    message->DestinationPortNetworkOrder[0] = 0x00;
    message->DestinationPortNetworkOrder[1] = 0x35;
    CHECK(FuriousWfpIsValidDatagramMessage(message, message->TotalSize));

    auto invalid = *message;
    invalid.Magic = 0;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    invalid = *message;
    invalid.Version++;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    invalid = *message;
    invalid.HeaderSize--;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    invalid = *message;
    invalid.TotalSize++;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    invalid = *message;
    invalid.PayloadSize = FURIOUS_WFP_DATAGRAM_MAX_PAYLOAD + 1;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, sizeof(invalid)));
    invalid = *message;
    invalid.Protocol = 6;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    invalid = *message;
    invalid.AddressFamily = 5;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    invalid = *message;
    invalid.SourceAddress[15] = 1;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    invalid = *message;
    invalid.Reserved[1] = 1;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    invalid = *message;
    invalid.FlowId = 0;
    CHECK(!FuriousWfpIsValidDatagramMessage(&invalid, invalid.TotalSize));
    CHECK(!FuriousWfpIsValidDatagramMessage(nullptr, sizeof(*message)));
    CHECK(!FuriousWfpIsValidDatagramMessage(message, sizeof(*message) - 1));

    message->AddressFamily = FURIOUS_WFP_DATAGRAM_FAMILY_IPV6;
    message->SourceAddress[15] = 1;
    CHECK(FuriousWfpIsValidDatagramMessage(message, message->TotalSize));
    message->MessageType = FURIOUS_WFP_DATAGRAM_MESSAGE_BROKER_REPLY;
    message->Direction = FURIOUS_WFP_DATAGRAM_DIRECTION_INBOUND;
    CHECK(FuriousWfpIsValidDatagramMessage(message, message->TotalSize));
    return 0;
}
