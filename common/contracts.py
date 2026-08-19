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
    encrypted_files: int = 0                    # distinct files whose final write is high-entropy
    encrypted_in_place: int = 0                 # existing files overwritten in place, high-entropy (naive-rule signal)
    encrypted_outcome: int = 0                  # victims ending high-entropy by any mechanism (behavior class)
    max_encrypted_per_pid: int = 0              # most victims a single pid encrypted (per_process rule)
    max_rate_in_window: int = 0                 # most victims encrypted within the rate window T (rate_windowed rule)
    encrypted_outcome_fs: int = 0               # victims ending high-entropy measured from filesystem bytes (Phase 3; 0 until then)
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


@dataclass
class RuleScore:
    """One row of a robustness scorecard: how a single behavioral rule fared
    against the mechanism toolbox. See ARCHITECTURE.md §11 (`rule_verdict`,
    `scorecard` events)."""

    rule: str
    evaded: bool
    evasion_depth: Optional[int]
    mechanism_that_evaded: Optional[str]
    behavior_preserved_at_evasion: bool
    provenance: Provenance
    # Phase 2: opt-in LLM overlay (HYDRA_SCORE_LLM=1) — did the adversary
    # INDEPENDENTLY discover an evasion for this rule from just the fired
    # rule name and the plain seed (not told which toolbox mechanism to use)?
    # Additive/backward-compatible: both default so existing callers building
    # a RuleScore without them (and existing serialized scorecards) still work.
    llm_evaded: bool = False
    llm_note: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Scorecard:
    """End-of-run leaderboard for the robustness-scorer mode. See
    ARCHITECTURE.md §11 (`scorecard` event)."""

    mode: str
    total_iterations: int
    rules: list[RuleScore] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "total_iterations": self.total_iterations,
            "rules": [r.to_dict() for r in self.rules],
        }
