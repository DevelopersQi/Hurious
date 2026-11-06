"""Validate the Python WFP IPC ABI without requiring Windows or a driver."""

from __future__ import annotations

import struct
import unittest

from Furious.Service.WfpIpcClient import (
    COMMAND_CLEAR_ENDPOINT_CONFIG,
    COMMAND_SET_ENDPOINT_CONFIG,
    COMMAND_STATUS,
    IPC_MAGIC,
    IPC_VERSION,
    REDIRECT_FLAG_IPV4,
    REDIRECT_FLAG_TCP,
    WfpIpcClient,
    WfpIpcProtocolError,
    WfpIpcRemoteError,
    build_request,
    pack_endpoint_config,
    parse_response,
)


class _Transport:
    def __init__(self, status=0, response_mutator=None):
        self.status = status
        self.response_mutator = response_mutator
        self.request = None

    def exchange(self, request):
        self.request = bytes(request)
        magic, version, header_size, total_size, command, request_id = (
            struct.unpack("<IHHIIQ", request[:24])
        )
        response = struct.pack(
            "<IHHIIQII",
            magic, version, 24, 32, command, request_id, self.status, 4,
        )
        return self.response_mutator(response) if self.response_mutator else response


class WfpIpcClientTest(unittest.TestCase):
    def testRequestUsesStableLittleEndianHeaderAndUniqueRequestId(self):
        first = build_request(COMMAND_STATUS, request_id=11)
        second = build_request(COMMAND_STATUS, request_id=12)

        self.assertEqual(
            struct.unpack("<IHHIIQ", first),
            (IPC_MAGIC, IPC_VERSION, 24, 24, COMMAND_STATUS, 11),
        )
        self.assertNotEqual(first, second)

    def testEndpointConfigMatchesTheNativeSeventySixByteAbi(self):
        payload = pack_endpoint_config(
            backend=1,
            flags=REDIRECT_FLAG_IPV4 | REDIRECT_FLAG_TCP,
            proxy_process_id=1234,
            policy_generation=9,
            tcp_port_v4=2080,
            excluded_process_ids=(2345, 3456),
        )

        self.assertEqual(len(payload), 76)
        values = struct.unpack("<IIIIIIQHHHHI8I", payload)
        self.assertEqual(values[:7], (76, 2, 1, 5, 1234, 0, 9))
        self.assertEqual(values[7:12], (2080, 0, 0, 0, 2))
        self.assertEqual(values[12:], (2345, 3456, 0, 0, 0, 0, 0, 0))

    def testEndpointConfigRejectsInvalidExclusionLists(self):
        base = dict(
            backend=1,
            flags=REDIRECT_FLAG_IPV4 | REDIRECT_FLAG_TCP,
            proxy_process_id=1234,
            policy_generation=1,
            tcp_port_v4=2080,
        )
        for pids in ((0,), (1234,), (2345, 2345), tuple(range(1, 10))):
            with self.subTest(pids=pids):
                with self.assertRaises(ValueError):
                    pack_endpoint_config(**base, excluded_process_ids=pids)

    def testEndpointConfigRejectsPortFlagMismatch(self):
        with self.assertRaisesRegex(ValueError, "ports do not match"):
            pack_endpoint_config(
                backend=1,
                flags=REDIRECT_FLAG_IPV4 | REDIRECT_FLAG_TCP,
                proxy_process_id=1234,
                policy_generation=1,
            )

    def testClientRoundTripsAStatusResponse(self):
        transport = _Transport()
        response = WfpIpcClient(transport).status()

        self.assertEqual(response.command, COMMAND_STATUS)
        self.assertEqual(response.win32_status, 0)
        self.assertEqual(len(transport.request), 24)

    def testClientRejectsMismatchedResponseIdentity(self):
        def corrupt(response):
            return response[:16] + struct.pack("<Q", 999) + response[24:]

        with self.assertRaises(WfpIpcProtocolError):
            WfpIpcClient(_Transport(response_mutator=corrupt)).status()

    def testResponseParserRejectsMalformedProtocolHeaders(self):
        request_id = 77
        valid = struct.pack(
            "<IHHIIQII",
            IPC_MAGIC, IPC_VERSION, 24, 32, COMMAND_STATUS, request_id, 0, 1,
        )
        corruptions = (
            valid[:0] + struct.pack("<I", 0) + valid[4:],
            valid[:4] + struct.pack("<H", IPC_VERSION + 1) + valid[6:],
            valid[:6] + struct.pack("<H", 20) + valid[8:],
            valid[:8] + struct.pack("<I", 31) + valid[12:],
        )
        for response in corruptions:
            with self.subTest(response=response):
                with self.assertRaises(WfpIpcProtocolError):
                    parse_response(response, COMMAND_STATUS, request_id)

    def testRequestRejectsOversizedPayload(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            build_request(COMMAND_STATUS, b"x" * (64 * 1024))

    def testClientRaisesOnServiceCommandFailure(self):
        with self.assertRaises(WfpIpcRemoteError) as caught:
            WfpIpcClient(_Transport(status=5)).status()
        self.assertEqual(caught.exception.status, 5)

    def testSetAndClearEndpointCommandsUseExpectedCommandIds(self):
        transport = _Transport()
        client = WfpIpcClient(transport)
        payload = pack_endpoint_config(
            backend=1,
            flags=REDIRECT_FLAG_IPV4 | REDIRECT_FLAG_TCP,
            proxy_process_id=1234,
            policy_generation=1,
            tcp_port_v4=2080,
        )
        client.setEndpointConfig(payload)
        self.assertEqual(struct.unpack("<I", transport.request[12:16])[0],
                         COMMAND_SET_ENDPOINT_CONFIG)
        client.clearEndpointConfig()
        self.assertEqual(struct.unpack("<I", transport.request[12:16])[0],
                         COMMAND_CLEAR_ENDPOINT_CONFIG)


if __name__ == "__main__":
    unittest.main()
