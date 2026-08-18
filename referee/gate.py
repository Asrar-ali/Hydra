"""Behavior-preservation gate. See ARCHITECTURE.md §5.1.

Decides, from the arena's observations (never from the source), whether a
candidate still exhibits the ransomware behavior class. Uses the same thresholds
as the Falco rule so the two can never disagree.
"""
from __future__ import annotations

from common.config import FILES_K
from common.contracts import ArenaObservation


def behavior_preserved(obs: ArenaObservation) -> bool:
    """The candidate still does the ransomware behavior: it bulk-rewrote at least
    FILES_K files with high-entropy content. Same signal the behavioral detector
    keys on, so gate and detector can never disagree."""
    return bool(obs.compiled and obs.encrypted_files >= FILES_K)
