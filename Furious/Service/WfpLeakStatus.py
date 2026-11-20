# Copyright (C) 2024–present  Loren Eteval & contributors
#
# This file is part of Furious and is distributed under the GNU General Public
# License, version 3 or (at your option) any later version.

"""Conservative security-state evaluation for WFP traffic leak monitoring.

This module evaluates monitor evidence; it does not capture packets itself.
A green/protected state is possible only when the driver and proxy are healthy,
telemetry is fresh, and every required traffic dimension is covered.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet, Tuple


REQUIRED_LEAK_COVERAGE = frozenset({
    "tcp",
    "udp",
    "dns",
    "ipv4",
    "ipv6",
})


class WfpLeakState(str, Enum):
    PROTECTED = "protected"
    LEAK_EXPOSED = "leak_exposed"
    LEAK_BLOCKED = "leak_blocked"
    DRIVER_UNAVAILABLE = "driver_unavailable"
    PROXY_UNAVAILABLE = "proxy_unavailable"
    TELEMETRY_STALE = "telemetry_stale"
    COVERAGE_INCOMPLETE = "coverage_incomplete"


@dataclass(frozen=True)
class WfpLeakEvent:
    """One positively identified flow that bypassed the proxy policy."""

    timestamp: float
    protocol: str
    address_family: str
    process_name: str
    process_id: int
    remote_address: str
    remote_port: int
    reason: str


@dataclass(frozen=True)
class WfpLeakSnapshot:
    """Immutable inputs collected by the WFP monitor and proxy supervisor."""

    driver_healthy: bool
    proxy_healthy: bool
    telemetry_fresh: bool
    coverage: FrozenSet[str]
    bypass_events: Tuple[WfpLeakEvent, ...] = ()
    kill_switch_enabled: bool = False
    kill_switch_active: bool = False

    def __post_init__(self):
        normalized = frozenset(str(item).strip().lower() for item in self.coverage)
        unknown = normalized.difference(REQUIRED_LEAK_COVERAGE)
        if unknown:
            raise ValueError("unsupported WFP leak coverage dimensions: " + ", ".join(sorted(unknown)))
        object.__setattr__(self, "coverage", normalized)
        object.__setattr__(self, "bypass_events", tuple(self.bypass_events))


@dataclass(frozen=True)
class WfpLeakAssessment:
    """User-facing state plus the evidence needed to explain that state."""

    state: WfpLeakState
    missing_coverage: FrozenSet[str]
    bypass_events: Tuple[WfpLeakEvent, ...]
    kill_switch_enabled: bool
    kill_switch_active: bool

    @property
    def is_protected(self) -> bool:
        return self.state is WfpLeakState.PROTECTED

    @property
    def has_confirmed_leak(self) -> bool:
        return self.state in (WfpLeakState.LEAK_EXPOSED, WfpLeakState.LEAK_BLOCKED)


def assess_wfp_leak(snapshot: WfpLeakSnapshot) -> WfpLeakAssessment:
    """Return a conservative status; never infer safety from missing telemetry."""
    missing = REQUIRED_LEAK_COVERAGE.difference(snapshot.coverage)

    if snapshot.bypass_events:
        state = (
            WfpLeakState.LEAK_BLOCKED
            if snapshot.kill_switch_enabled and snapshot.kill_switch_active
            else WfpLeakState.LEAK_EXPOSED
        )
    elif not snapshot.driver_healthy:
        state = WfpLeakState.DRIVER_UNAVAILABLE
    elif not snapshot.proxy_healthy:
        state = WfpLeakState.PROXY_UNAVAILABLE
    elif not snapshot.telemetry_fresh:
        state = WfpLeakState.TELEMETRY_STALE
    elif missing:
        state = WfpLeakState.COVERAGE_INCOMPLETE
    else:
        state = WfpLeakState.PROTECTED

    return WfpLeakAssessment(
        state=state,
        missing_coverage=frozenset(missing),
        bypass_events=snapshot.bypass_events,
        kill_switch_enabled=bool(snapshot.kill_switch_enabled),
        kill_switch_active=bool(snapshot.kill_switch_active),
    )
