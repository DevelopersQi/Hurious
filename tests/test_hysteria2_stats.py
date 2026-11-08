# Copyright (C) 2024–present  Loren Eteval & contributors <loren.eteval@proton.me>
#
# This file is part of Furious.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Verify local Hysteria 2 traffic snapshots and provider lifecycle."""

from __future__ import annotations

from Furious.Backends.Hysteria2.Stats import (
    HYSTERIA2_STATS_MAX_AGE_SECONDS,
    Hysteria2StatsProvider,
    Hysteria2StatsTarget,
    queryHysteria2TrafficStats,
)

import json
import os
import tempfile
import time
import unittest


class _Runtime:
    def __init__(self, path):
        self.hysteria2StatsFile = path


class Hysteria2LocalTrafficStatsTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.directory.name, 'traffic.json')
        self.target = Hysteria2StatsTarget(self.path)

    def tearDown(self):
        self.directory.cleanup()

    def writeSnapshot(self, *, tx=1234, rx=5678, updatedAt=None):
        if updatedAt is None:
            updatedAt = int(time.time() * 1000)
        with open(self.path, 'w', encoding='utf-8') as stream:
            json.dump(
                {'tx': tx, 'rx': rx, 'updatedAt': updatedAt},
                stream,
            )

    def testReadsClientLocalPayloadCounters(self):
        self.writeSnapshot()
        counters = queryHysteria2TrafficStats(self.target)
        self.assertEqual((counters.uplink, counters.downlink), (1234, 5678))

    def testProviderUsesRuntimeOwnedFileWithoutServerSettings(self):
        self.writeSnapshot()
        provider = Hysteria2StatsProvider()
        monitor = provider.monitorForRuntime(_Runtime(self.path))
        self.assertIsNotNone(monitor)
        self.assertEqual(
            monitor.query(monitor.target),
            queryHysteria2TrafficStats(self.target),
        )
        self.assertTrue(provider.workerSafe)

    def testMissingStaleMalformedAndOversizedSnapshotsAreUnavailable(self):
        self.assertIsNone(queryHysteria2TrafficStats(self.target))

        self.writeSnapshot(
            updatedAt=int(
                (time.time() - HYSTERIA2_STATS_MAX_AGE_SECONDS - 1) * 1000
            )
        )
        self.assertIsNone(queryHysteria2TrafficStats(self.target))

        with open(self.path, 'w', encoding='utf-8') as stream:
            stream.write('{')
        self.assertIsNone(queryHysteria2TrafficStats(self.target))

        with open(self.path, 'w', encoding='utf-8') as stream:
            stream.write('x' * 70000)
        self.assertIsNone(queryHysteria2TrafficStats(self.target))

    def testInvalidCountersAreRejectedRatherThanShownAsZero(self):
        for tx, rx in ((True, 1), (-1, 2), (1, '2'), (None, 2)):
            with self.subTest(tx=tx, rx=rx):
                self.writeSnapshot(tx=tx, rx=rx)
                self.assertIsNone(queryHysteria2TrafficStats(self.target))

    def testRuntimeWithoutCounterFileDoesNotAdvertiseMonitor(self):
        provider = Hysteria2StatsProvider()
        self.assertIsNone(provider.monitorForRuntime(_Runtime('')))


if __name__ == '__main__':
    unittest.main()
