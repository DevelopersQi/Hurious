#include "../WfpTcpRedirect.h"

#include <cassert>
#include <cstdint>
#include <vector>

namespace {

FURIOUS_WFP_REDIRECT_CONTEXT MakeContext(
    FURIOUS_WFP_U16 family,
    FURIOUS_WFP_U8 protocol) {
    FURIOUS_WFP_REDIRECT_CONTEXT value = {};
    value.Magic = FURIOUS_WFP_REDIRECT_CONTEXT_MAGIC;
    value.Size = sizeof(value);
    value.AbiVersion = FURIOUS_WFP_REDIRECT_ABI_VERSION;
    value.AddressFamily = family;
    value.Protocol = protocol;
    value.OriginalPortNetworkOrder = htons(443);
    value.OriginalProcessId = 1234;
    value.PolicyGeneration = 9;
    return value;
}

void TestIpv4ConnectRequest() {
    auto context = MakeContext(
        FURIOUS_WFP_REDIRECT_FAMILY_V4,
        FURIOUS_WFP_REDIRECT_PROTOCOL_TCP);
    context.OriginalAddress[0] = 192;
    context.OriginalAddress[1] = 0;
    context.OriginalAddress[2] = 2;
    context.OriginalAddress[3] = 10;

    std::vector<std::uint8_t> request;
    assert(furious::wfp::broker::BuildSocks5ConnectRequest(context, request));
    const std::vector<std::uint8_t> expected = {
        0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10, 0x01, 0xBB
    };
    assert(request == expected);
}

void TestIpv6ConnectRequest() {
    auto context = MakeContext(
        FURIOUS_WFP_REDIRECT_FAMILY_V6,
        FURIOUS_WFP_REDIRECT_PROTOCOL_TCP);
    context.OriginalAddress[0] = 0x20;
    context.OriginalAddress[1] = 0x01;
    context.OriginalAddress[15] = 0x01;

    std::vector<std::uint8_t> request;
    assert(furious::wfp::broker::BuildSocks5ConnectRequest(context, request));
    assert(request.size() == 22);
    assert(request[0] == 0x05 && request[1] == 0x01);
    assert(request[2] == 0x00 && request[3] == 0x04);
    assert(request[4] == 0x20 && request[5] == 0x01);
    assert(request[19] == 0x01);
    assert(request[20] == 0x01 && request[21] == 0xBB);
}

void TestRejectsInvalidOrUdpContext() {
    auto context = MakeContext(
        FURIOUS_WFP_REDIRECT_FAMILY_V4,
        FURIOUS_WFP_REDIRECT_PROTOCOL_TCP);
    context.OriginalAddress[0] = 203;
    context.OriginalAddress[1] = 0;
    context.OriginalAddress[2] = 113;
    context.OriginalAddress[3] = 7;

    std::vector<std::uint8_t> request;
    context.Magic ^= 1;
    assert(!furious::wfp::broker::BuildSocks5ConnectRequest(context, request));
    assert(request.empty());

    context.Magic ^= 1;
    context.Protocol = FURIOUS_WFP_REDIRECT_PROTOCOL_UDP;
    assert(!furious::wfp::broker::BuildSocks5ConnectRequest(context, request));
    assert(request.empty());
}

} // namespace

void TestBrokerServerLifecycle();
void TestBrokerConcurrentStartStopIsSerialized();
void TestBrokerStopsWhileAcceptingConnections();

int main() {
    TestIpv4ConnectRequest();
    TestIpv6ConnectRequest();
    TestRejectsInvalidOrUdpContext();
    TestBrokerServerLifecycle();
    TestBrokerConcurrentStartStopIsSerialized();
    TestBrokerStopsWhileAcceptingConnections();
    return 0;
}
