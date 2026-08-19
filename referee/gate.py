"""Behavior-preservation gate. See ARCHITECTURE.md §5.1.

Decides, from the arena's observations (never from the source), whether a
candidate still exhibits the ransomware behavior class. Uses the same thresholds
as the Falco rule so the two can never disagree.
"""
from __future__ import annotations

from common.config import FILES_K
from common.contracts import ArenaObservation


def _outcome_count(obs: ArenaObservation) -> int:
    """Files the owner can no longer recover, counted by OUTCOME rather than by
    mechanism: victims that ended high-entropy however it was done (direct write,
    or write-to-temp + rename). Falls back to the legacy write()-based count when
    the mechanism-aware fact isn't populated (fake mode / hand-built observations),
    so existing callers are unaffected."""
    return obs.encrypted_outcome or obs.encrypted_files


def behavior_preserved(obs: ArenaObservation) -> bool:
    """The candidate still does the ransomware behavior: at least FILES_K of the
    owner's files ended up high-entropy (unrecoverable), by ANY mechanism.

    Deliberately keys on the OUTCOME, not on the write()-in-place signal a naive
    behavioral rule uses. That is the whole point: an adversary can change the
    mechanism to evade the naive rule (drive encrypted_in_place to 0) while this
    gate still passes (encrypted_outcome stays high) — i.e. it evaded detection
    WITHOUT abandoning the behavior. See detectors/falco_detector.evaluate_naive
    vs evaluate_robust."""
    return bool(obs.compiled and _outcome_count(obs) >= FILES_K)
