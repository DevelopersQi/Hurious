import struct
import unittest
from types import SimpleNamespace

from Furious.Service.WfpEndpointConfig import build_endpoint_config


class WfpEndpointConfigTests(unittest.TestCase):
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
