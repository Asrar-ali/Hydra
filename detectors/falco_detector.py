"""Behavioral detector.

Lane 2 owns this. The rule keys on the ransomware behavior class — a process
that rewrites many files with high-entropy content — evaluated from the arena's
observations, NOT from any prior sample. That is what makes it behavioral rather
than "seen before". See ARCHITECTURE.md §9.2 and hydra_ransomware.yaml.

The real path evaluates the Falco rule against the syscall stream (eBPF), with a
strace fallback. This function evaluates the same rule logic against an
ArenaObservation so it works in both modes.

Contract: evaluate(obs: ArenaObservation) -> "FIRED" | "SILENT"
"""
from __future__ import annotations

from common.config import ENTROPY_H, FILES_K
from common.contracts import ArenaObservation, BehaviorVerdict
from common.logging import get_logger

log = get_logger("falco")


def evaluate(obs: ArenaObservation) -> BehaviorVerdict:
    """FIRED when the run rewrote at least FILES_K files with mean entropy at or
    above ENTROPY_H. Authored blind — it never sees a generation to seed on."""
    if not obs.compiled:
        return "SILENT"
    if obs.files_written >= FILES_K and obs.mean_entropy >= ENTROPY_H:
        return "FIRED"
    return "SILENT"

    # TODO(lane2): when Falco/eBPF is available in Colima, evaluate the rule in
    # hydra_ransomware.yaml against the live syscall stream; fall back to
    # deriving files_written/mean_entropy from the strace trace (arena §8).
