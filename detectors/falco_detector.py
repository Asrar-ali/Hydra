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


def evaluate_naive(obs: ArenaObservation) -> BehaviorVerdict:
    """Naive canary rule — fires only on IN-PLACE rewrite of existing files with
    high-entropy content (a file overwritten after it already held content).

    This is a common, reasonable-looking real heuristic: EDR canaries and
    honeyfile monitors alert when a *watched, existing* file is modified with
    high-entropy bytes. Its blind spot is the mechanism: an adversary that
    replaces each victim via write-to-temp + rename() never overwrites an
    existing file in place, so this rule stays SILENT while every victim still
    ends encrypted. That is the evasion Hydra demonstrates."""
    if not obs.compiled:
        return "SILENT"
    return "FIRED" if obs.encrypted_in_place >= FILES_K else "SILENT"


def evaluate_robust(obs: ArenaObservation) -> BehaviorVerdict:
    """Robust rule — fires when at least FILES_K distinct victim files END
    high-entropy by ANY mechanism. It follows rename() to the real destination
    and ignores scratch temps, so it keys on the behavior CLASS (the owner's
    files became unrecoverable), not on which syscall did it. A mechanism swap
    that evades ``evaluate_naive`` does not evade this."""
    if not obs.compiled:
        return "SILENT"
    return "FIRED" if obs.encrypted_outcome >= FILES_K else "SILENT"
