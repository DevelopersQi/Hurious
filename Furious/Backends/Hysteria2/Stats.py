# Copyright (C) 2024–present  Loren Eteval & contributors <loren.eteval@proton.me>
#
# This file is part of Furious.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Read Hysteria 2's local client-side proxy payload counters."""

from __future__ import annotations

from Furious.Plugins.API import (
    TrafficCounters,
    TrafficStatsMonitor,
    TrafficStatsProvider,
)

from dataclasses import dataclass
from typing import Optional
import json
import os
import time

from .Process import Hysteria2

__all__ = [
    'Hysteria2StatsProvider',
    'Hysteria2StatsTarget',
    'queryHysteria2TrafficStats',
]

HYSTERIA2_STATS_MAX_AGE_SECONDS = 8
HYSTERIA2_STATS_MAX_FILE_SIZE = 64 * 1024


@dataclass(frozen=True)
class Hysteria2StatsTarget:
    """Identify one runtime-owned local counter snapshot file."""

    path: str


def _counter(value) -> Optional[int]:
    """Accept only non-negative integer byte counters."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def queryHysteria2TrafficStats(
    target: Hysteria2StatsTarget,
) -> Optional[TrafficCounters]:
    """Read a fresh snapshot written by the embedded local Hysteria client."""
    if not isinstance(target, Hysteria2StatsTarget) or not target.path:
        return None

    try:
        if os.path.getsize(target.path) > HYSTERIA2_STATS_MAX_FILE_SIZE:
            return None

        with open(target.path, 'rb') as stream:
            content = stream.read(HYSTERIA2_STATS_MAX_FILE_SIZE + 1)

        if len(content) > HYSTERIA2_STATS_MAX_FILE_SIZE:
            return None

        payload = json.loads(content)
        if not isinstance(payload, dict):
            return None

        updatedAt = payload.get('updatedAt')
        if isinstance(updatedAt, bool) or not isinstance(updatedAt, int):
            return None

        age = time.time() - updatedAt / 1000.0
        if age < -5 or age > HYSTERIA2_STATS_MAX_AGE_SECONDS:
            return None

        uplink = _counter(payload.get('tx'))
        downlink = _counter(payload.get('rx'))
        if uplink is None or downlink is None:
            return None

        return TrafficCounters(uplink=uplink, downlink=downlink)
    except (OSError, TypeError, ValueError, OverflowError):
        return None


class Hysteria2StatsProvider(TrafficStatsProvider):
    """Expose runtime-local payload counters through shared traffic metrics."""

    providerId = 'official.hysteria2.local-stats'
    runtimeTypes = (Hysteria2,)
    workerSafe = True

    def monitorForRuntime(self, runtime) -> Optional[TrafficStatsMonitor]:
        """Return a monitor only for a runtime with its own counter file."""
        path = getattr(runtime, 'hysteria2StatsFile', None)
        if not isinstance(path, str) or not path:
            return None

        return TrafficStatsMonitor(
            query=queryHysteria2TrafficStats,
            target=Hysteria2StatsTarget(path),
        )
