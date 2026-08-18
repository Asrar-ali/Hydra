"""Behavior-preservation gate. See ARCHITECTURE.md §5.1.

Decides, from the arena's observations (never from the source), whether a
candidate still exhibits the ransomware behavior class. Uses the same thresholds
as the Falco rule so the two can never disagree.
"""
from __future__ import annotations

from common.config import ENTROPY_H, FILES_K
from common.contracts import ArenaObservation


def behavior_preserved(obs: ArenaObservation) -> bool:
    return bool(
        obs.compiled and obs.files_written >= FILES_K and obs.mean_entropy >= ENTROPY_H
    )
