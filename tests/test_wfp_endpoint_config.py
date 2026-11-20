import struct
import unittest
from types import SimpleNamespace

from Furious.Service.WfpEndpointConfig import (
    UDP_WFP_REDIRECT_EXPERIMENTAL_ENABLED,
    build_endpoint_config,
)


class WfpEndpointConfigTests(unittest.TestCase):
    def test_live_udp_redirect_is_enabled_for_experimental_real_machine_validation(self):
        self.assertTrue(UDP_WFP_REDIRECT_EXPERIMENTAL_ENABLED)

    def test_builds_dual_stack_tcp_endpoint_from_runtime_snapshot(self):
        snapshot = SimpleNamespace(
            generation=23,
            excluded_process_ids=(1111, 2222),
        )

        payload = build_endpoint_config(
            snapshot,
            backend=2,
            broker_process_id=4321,
            tcp_port_v4=32001,
            tcp_port_v6=32002,
        )

        self.assertEqual(len(payload), 76)
        values = struct.unpack("<IIIIIIQHHHHI8I", payload)
        self.assertEqual(values[:7], (76, 2, 2, 7, 4321, 0, 23))
        self.assertEqual(values[7:12], (32001, 0, 32002, 0, 2))
        self.assertEqual(values[12:], (1111, 2222, 0, 0, 0, 0, 0, 0))

    def test_builds_dual_stack_tcp_and_udp_endpoint(self):
        snapshot = SimpleNamespace(
            generation=24,
            excluded_process_ids=(1111, 2222),
        )
        payload = build_endpoint_config(
            snapshot,
            backend=2,
            broker_process_id=4321,
            tcp_port_v4=32001,
            tcp_port_v6=32002,
            udp_port_v4=33001,
            udp_port_v6=33002,
        )
        values = struct.unpack("<IIIIIIQHHHHI8I", payload)
        self.assertEqual(values[3], 15)
        self.assertEqual(values[7:12], (32001, 33001, 32002, 33002, 2))

    def test_rejects_mismatched_udp_listener_families(self):
        snapshot = SimpleNamespace(generation=1, excluded_process_ids=(1111,))
        with self.assertRaisesRegex(ValueError, "families must match"):
            build_endpoint_config(
                snapshot, 1, 4321, 32001, 32002, udp_port_v4=33001
            )

    def test_requires_live_proxy_core_exclusions(self):
        snapshot = SimpleNamespace(
            generation=1,
            excluded_process_ids=(),
        )

        with self.assertRaisesRegex(ValueError, "live proxy-core PID"):
            build_endpoint_config(snapshot, 1, 4321, 32001, 0)

    def test_requires_at_least_one_listener(self):
        snapshot = SimpleNamespace(
            generation=1,
            excluded_process_ids=(1111,),
        )

        with self.assertRaisesRegex(ValueError, "at least one TCP listener"):
            build_endpoint_config(snapshot, 1, 4321, 0, 0)


if __name__ == "__main__":
    unittest.main()
