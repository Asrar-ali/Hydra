"""Shared data contracts — the seams that let the four lanes work in parallel.

These shapes are the agreement between lanes. Code against them, not against
another lane's internals. See ARCHITECTURE.md §7 (components), §10 (metrics),
§11 (SSE contract).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Literal, Optional

# Verdict vocabularies (kept as plain strings so they serialize cleanly to JSON).
SignatureVerdict = Literal["MATCH", "CLEAN"]      # YARA (signature)
BehaviorVerdict = Literal["FIRED", "SILENT"]      # Falco / strace behavioral rule
Provenance = Literal["seed", "offline", "llm"]    # what produced a candidate
TargetDetector = Literal["yara", "falco"]


@dataclass
class ArenaObservation:
    """What ``arena.run`` returns after compiling and running one candidate in
    the sandbox. This is Lane 1's output and Lane 2/4's input."""

    compiled: bool
    binary_sha256: Optional[str] = None
    binary_bytes: Optional[bytes] = None       # None in fake mode / on compile failure
    files_written: int = 0
    mean_entropy: float = 0.0                   # bits/byte, 0..8
    syscalls: list[str] = field(default_factory=list)
    stdout: str = ""
    exit_code: Optional[int] = None
    error: Optional[str] = None


@dataclass
class Feedback:
    """Referee -> adversary: why a candidate was caught and what to preserve.

    Lane 3 turns this into a rewrite prompt. See ARCHITECTURE.md §5.2."""

    detector: TargetDetector
    reason: str
    source: str


@dataclass
class IterationResult:
    """One row of ``results.json``. See ARCHITECTURE.md §10."""

    iteration: int
    track: int
    target_detector: Optional[TargetDetector]
    source_sha256: str
    compiled: bool
    behavior_preserved: bool
    files_written: int
    mean_entropy: float
    yara: SignatureVerdict
    falco: BehaviorVerdict
    provenance: Provenance

    def to_dict(self) -> dict:
        return asdict(self)
