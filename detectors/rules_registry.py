"""Registry of named behavioral rules — the detection-rule robustness scorer.

Lane 2/4 owns this. Each rule keys on ONE derived fact of ``ArenaObservation``,
so the scorer can hold every rule against the same mechanism toolbox and
measure how hard each is to evade. See ARCHITECTURE.md §9.2 and
``detectors/falco_detector.py`` for the underlying rule logic this registry
wraps and extends.

Rules with narrow, mechanism-specific keys (e.g. "was this file overwritten
IN PLACE?") are weak — a single mechanism swap (write-to-temp + rename())
evades them while the ransomware behavior never stops. The outcome-keyed rule
(``robust_outcome``) is the head that grows back: it follows rename() to the
real destination and keys on the behavior CLASS, not on which syscall did it.

Fixed evaluation order below is deliberate: weakest -> strongest.

Contract: RULES is a name -> RuleSpec map; evaluate_all(obs) runs every rule
against one ArenaObservation and returns {name: "FIRED" | "SILENT"}.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from common.config import FILES_K
from common.contracts import ArenaObservation, BehaviorVerdict
from detectors import falco_detector


@dataclass
class RuleSpec:
    """One named behavioral rule under test.

    ``keyed_fact`` names the single derived ArenaObservation fact this rule's
    verdict depends on — that fact is the rule's attack surface: an adversary
    that finds a mechanism which leaves it unchanged evades the rule without
    changing the ransomware behavior."""

    name: str
    desc: str
    keyed_fact: str
    evaluate: Callable[[ArenaObservation], BehaviorVerdict]


def _evaluate_write_content(obs: ArenaObservation) -> BehaviorVerdict:
    if not obs.compiled:
        return "SILENT"
    return "FIRED" if obs.encrypted_files >= FILES_K else "SILENT"


def _evaluate_rate_windowed(obs: ArenaObservation) -> BehaviorVerdict:
    if not obs.compiled:
        return "SILENT"
    return "FIRED" if getattr(obs, "max_rate_in_window", 0) >= FILES_K else "SILENT"


def _evaluate_per_process(obs: ArenaObservation) -> BehaviorVerdict:
    if not obs.compiled:
        return "SILENT"
    return "FIRED" if getattr(obs, "max_encrypted_per_pid", 0) >= FILES_K else "SILENT"


RULES: dict[str, RuleSpec] = {
    "naive_inplace": RuleSpec(
        name="naive_inplace",
        desc=(
            "Fires on existing files overwritten IN PLACE with high-entropy "
            "content; evaded by rename-swap (write-to-temp + rename())."
        ),
        keyed_fact="encrypted_in_place",
        evaluate=falco_detector.evaluate_naive,
    ),
    "write_content": RuleSpec(
        name="write_content",
        desc=(
            "Fires on any write() of high-entropy content, including scratch "
            "temps; evaded only by not writing (e.g. mmap)."
        ),
        keyed_fact="encrypted_files",
        evaluate=_evaluate_write_content,
    ),
    "rate_windowed": RuleSpec(
        name="rate_windowed",
        desc=(
            "Fires on >=K victims encrypted within a rate window T; evaded by "
            "throttling below the window's rate."
        ),
        keyed_fact="max_rate_in_window",
        evaluate=_evaluate_rate_windowed,
    ),
    "per_process": RuleSpec(
        name="per_process",
        desc=(
            "Fires on >=K victims encrypted by a single pid; evaded by "
            "fan-out across child processes."
        ),
        keyed_fact="max_encrypted_per_pid",
        evaluate=_evaluate_per_process,
    ),
    "robust_outcome": RuleSpec(
        name="robust_outcome",
        desc=(
            "Fires when >=K victims END high-entropy by ANY mechanism "
            "(follows rename, ignores temps); the head that grows back."
        ),
        keyed_fact="encrypted_outcome",
        evaluate=falco_detector.evaluate_robust,
    ),
}


def evaluate_all(obs: ArenaObservation) -> dict[str, BehaviorVerdict]:
    """Run every registered rule against one observation."""
    return {name: spec.evaluate(obs) for name, spec in RULES.items()}
