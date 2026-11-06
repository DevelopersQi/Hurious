"""Tests for immutable WFP runtime process snapshots."""

from __future__ import annotations

import unittest

from Furious.Service.WfpRuntimeSnapshot import WfpRuntimeSnapshot


class WfpRuntimeSnapshotTest(unittest.TestCase):
    def test_accepts_empty_snapshot_for_a_committed_generation(self):
        snapshot = WfpRuntimeSnapshot(1, ())

        self.assertEqual(snapshot.generation, 1)
        self.assertEqual(snapshot.excluded_process_ids, ())

    def test_requires_nonzero_uint64_generation(self):
        for generation in (0, -1, 1 << 64):
            with self.subTest(generation=generation):
                with self.assertRaises(ValueError):
                    WfpRuntimeSnapshot(generation, ())

    def test_requires_sorted_unique_nonzero_uint32_process_ids(self):
        for process_ids in ((0,), (-1,), (1 << 32,), (20, 10), (10, 10)):
            with self.subTest(process_ids=process_ids):
                with self.assertRaises(ValueError):
                    WfpRuntimeSnapshot(1, process_ids)

    def test_rejects_more_process_ids_than_the_native_abi_can_carry(self):
        with self.assertRaisesRegex(ValueError, "at most eight"):
            WfpRuntimeSnapshot(1, tuple(range(1, 10)))

    def test_normalizes_immutable_integer_values(self):
        snapshot = WfpRuntimeSnapshot("7", ["2", "9"])

        self.assertEqual(snapshot.generation, 7)
        self.assertEqual(snapshot.excluded_process_ids, (2, 9))
        with self.assertRaises((AttributeError, TypeError)):
            snapshot.generation = 8


if __name__ == "__main__":
    unittest.main()
