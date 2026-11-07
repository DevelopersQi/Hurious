# Copyright (C) 2024–present  Loren Eteval & contributors
#
# This file is part of Furious and is distributed under the GNU General Public
# License, version 3 or (at your option) any later version.

"""Immutable process-exclusion snapshots for the WFP control plane."""

from __future__ import annotations

from dataclasses import dataclass


MAX_WFP_EXCLUDED_PROCESS_IDS = 8
MAX_UINT32 = 0xFFFFFFFF
MAX_UINT64 = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True)
class WfpRuntimeSnapshot:
    """Bind one committed runtime generation to its live proxy-core PIDs."""

    generation: int
    excluded_process_ids: tuple[int, ...]

    def __post_init__(self):
        generation = int(self.generation)
        process_ids = tuple(int(pid) for pid in self.excluded_process_ids)

        if not 0 < generation <= MAX_UINT64:
            raise ValueError("WFP runtime generation must be a non-zero uint64")
        if len(process_ids) > MAX_WFP_EXCLUDED_PROCESS_IDS:
            raise ValueError("WFP supports at most eight excluded process IDs")
        if any(pid <= 0 or pid > MAX_UINT32 for pid in process_ids):
            raise ValueError("excluded process IDs must be non-zero uint32 values")
        if tuple(sorted(set(process_ids))) != process_ids:
            raise ValueError("excluded process IDs must be sorted and unique")

        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "excluded_process_ids", process_ids)

def collect_live_proxy_process_ids(runtimes, is_excluded_runtime=None):
    """Return only process IDs belonging to currently running proxy runtimes.

    A runtime may still expose its last PID briefly after its process exits but
    before the queued exit callback is handled. Such a PID must not remain in
    the WFP exclusion list, where Windows could reuse it for an unrelated app.
    """
    process_ids = set()
    for runtime in runtimes:
        if is_excluded_runtime is not None and is_excluded_runtime(runtime):
            continue

        is_running = getattr(runtime, "isRunning", None)
        if not callable(is_running):
            continue
        try:
            if not is_running():
                continue
        except Exception:
            # An uncertain process state is never safe to exclude from redirect.
            continue

        try:
            process_id = getattr(runtime, "processId", None)
        except Exception:
            continue
        if (
            isinstance(process_id, int)
            and not isinstance(process_id, bool)
            and 0 < process_id <= MAX_UINT32
        ):
            process_ids.add(process_id)

    return tuple(sorted(process_ids))

