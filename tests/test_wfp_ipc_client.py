"""Validate the Python WFP IPC ABI without requiring Windows or a driver."""

from __future__ import annotations

import struct
import unittest

from Furious.Service.WfpIpcClient import (
    COMMAND_CLEAR_ENDPOINT_CONFIG,
    MAX_MESSAGE_SIZE,
    COMMAND_SET_ENDPOINT_CONFIG,
    COMMAND_STATUS,
    COMMAND_START_BROKER,
    COMMAND_SET_POLICY,
    COMMAND_CLEAR_POLICY,
    COMMAND_STOP_BROKER,
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
    pack_broker_start_request,
    pack_application_routing_policy,
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
        broker_pid = 5678 if command == COMMAND_START_BROKER else 0
        port_v4 = 32001 if command == COMMAND_START_BROKER else 0
        port_v6 = 32002 if command == COMMAND_START_BROKER else 0
        response = struct.pack(
            "<IHHIIQIIIHH",
            magic, version, 24, 40, command, request_id, self.status, 4,
            broker_pid, port_v4, port_v6,
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

    def testBrokerStartRequestAcceptsOnlyLoopbackEndpoints(self):
        payload = pack_broker_start_request("127.0.0.1", 10808)
        self.assertEqual(len(payload), 32)
        size, version, family, flags, port, reserved, address = struct.unpack("<IIHHHH16s", payload)
        self.assertEqual((size, version, family, flags, port, reserved), (32, 1, 4, 3, 10808, 0))
        self.assertEqual(address[:4], bytes((127, 0, 0, 1)))
        self.assertEqual(address[4:], bytes(12))
        with self.assertRaisesRegex(ValueError, "loopback"):
            pack_broker_start_request("192.0.2.1", 10808)
        with self.assertRaises(ValueError):
            pack_broker_start_request("::1", 0)

    def testApplicationPolicySerializationMatchesNativeAbi(self):
        path = r"C:\Program Files\Furious\client.exe"
        rules = [{"priority": 10, "action": "proxy", "enabled": True, "image_path": path}]
        payload = pack_application_routing_policy(rules, 1, 77)
        self.assertEqual(len(payload), 24 + 1060)
        size, abi, count, backend, generation = struct.unpack("<IIIIQ", payload[:24])
        self.assertEqual((size, abi, count, backend, generation), (24, 1, 1, 1, 77))
        values = struct.unpack("<IIIII520H", payload[24:])
        self.assertEqual(values[:5], (1060, 10, 1, 1, len(path)))
        decoded = bytes().join(struct.pack("<H", unit) for unit in values[5:5 + values[4]])
        self.assertEqual(decoded.decode("utf-16le"), path)
        self.assertEqual(values[5 + values[4]], 0)

    def testApplicationPolicyRejectsInvalidRulesAndSupportsMaximumCount(self):
        with self.assertRaisesRegex(ValueError, "absolute Windows path"):
            pack_application_routing_policy([{"priority": 1, "path": "relative.exe"}], 1, 1)
        with self.assertRaisesRegex(ValueError, "backend"):
            pack_application_routing_policy([{"priority": 1, "action": "proxy", "path": r"C:\a.exe"}], 0, 1)
        with self.assertRaisesRegex(ValueError, "priorities"):
            pack_application_routing_policy([
                {"priority": 1, "path": r"C:\a.exe"},
                {"priority": 1, "path": r"C:\b.exe"},
            ], 1, 1)
        rules = [{"priority": index, "path": r"C:\Apps\app%d.exe" % index} for index in range(256)]
        payload = pack_application_routing_policy(rules, 1, 2)
        self.assertLess(len(payload) + 24, MAX_MESSAGE_SIZE)

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
        self.assertEqual(response.broker_process_id, 0)
        self.assertEqual(len(transport.request), 24)

    def testClientRejectsMismatchedResponseIdentity(self):
        def corrupt(response):
            return response[:16] + struct.pack("<Q", 999) + response[24:]

        with self.assertRaises(WfpIpcProtocolError):
            WfpIpcClient(_Transport(response_mutator=corrupt)).status()

    def testResponseParserRejectsInconsistentBrokerTelemetry(self):
        request_id = 19
        malformed = struct.pack(
            "<IHHIIQIIIHH", IPC_MAGIC, IPC_VERSION, 24, 40,
            COMMAND_STATUS, request_id, 0, 4, 1234, 0, 0,
        )
        with self.assertRaisesRegex(WfpIpcProtocolError, "telemetry"):
            parse_response(malformed, COMMAND_STATUS, request_id)

    def testResponseParserRejectsMalformedProtocolHeaders(self):
        request_id = 77
        valid = struct.pack(
            "<IHHIIQIIIHH",
            IPC_MAGIC, IPC_VERSION, 24, 40, COMMAND_STATUS, request_id, 0, 1, 0, 0, 0,
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
        broker = client.startBroker("127.0.0.1", 10808)
        self.assertEqual(broker.broker_process_id, 5678)
        self.assertEqual(broker.tcp_port_v4, 32001)
        self.assertEqual(struct.unpack("<I", transport.request[12:16])[0],
                         COMMAND_START_BROKER)
        client.stopBroker()
        self.assertEqual(struct.unpack("<I", transport.request[12:16])[0],
                         COMMAND_STOP_BROKER)
        client.setPolicy([], 0, 1)
        self.assertEqual(struct.unpack("<I", transport.request[12:16])[0],
                         COMMAND_SET_POLICY)
        client.clearPolicy()
        self.assertEqual(struct.unpack("<I", transport.request[12:16])[0],
                         COMMAND_CLEAR_POLICY)
        client.setPolicy([], 0, 1)
        self.assertEqual(struct.unpack("<I", transport.request[12:16])[0],
                         COMMAND_SET_POLICY)
        client.clearPolicy()
        self.assertEqual(struct.unpack("<I", transport.request[12:16])[0],
                         COMMAND_CLEAR_POLICY)


if __name__ == "__main__":
    unittest.main()
