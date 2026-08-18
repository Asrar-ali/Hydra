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

from common.config import FILES_K
from common.contracts import ArenaObservation, BehaviorVerdict
from common.logging import get_logger

log = get_logger("falco")


def evaluate(obs: ArenaObservation) -> BehaviorVerdict:
    """FIRED when the run rewrote at least FILES_K distinct files with
    high-entropy final content — the bulk-encryption signal of ransomware.

    Keying on the count of *encrypted* files (not just files written, and not a
    diluted mean) is what makes this specific: a program that writes many plain
    files does not fire, and a program that writes a couple of high-entropy files
    does not fire. Authored blind — it never sees a generation to seed on."""
    if not obs.compiled:
        return "SILENT"
    return "FIRED" if obs.encrypted_files >= FILES_K else "SILENT"

    # TODO: when Falco/eBPF is available in Colima, evaluate the rule in
    # hydra_ransomware.yaml against the live syscall stream (the entropy signal is
    # fed from the strace-derived arena facts).
