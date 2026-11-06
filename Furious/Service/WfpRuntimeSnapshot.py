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
