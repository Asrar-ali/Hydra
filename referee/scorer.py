"""The robustness-scorer loop. See ARCHITECTURE.md §11.

Drives Hydra's "detection-rule robustness scorer" mode: for each behavioral
rule in ``detectors/rules_registry.RULES`` (naive_inplace, rate_windowed,
per_process, write_content, robust_outcome), search the mechanism toolbox
(adversary/) for the shallowest mechanism that evades it while behavior is
preserved, and record that evasion depth. The result is a leaderboard —
which rules are robust (never evaded) and which fall to a cheap mechanism.

Phase 0: this module is a STUB. ``score_rules_events`` returns CANNED data
(no arena runs, no real detector calls) so downstream lanes (dashboard,
CLI) can build against the event shapes before the real search is wired up.

Mirrors ``referee/loop.py``'s ``run_events``/``run_loop`` shape: a generator
yielding ``(event_name, data_dict)`` tuples per the SSE contract, and a
blocking wrapper that drains it into a plain dict.

    python3 -c "from referee.scorer import run_scorecard; print(run_scorecard(12))"
"""
from __future__ import annotations

from typing import Iterator

from common.contracts import RuleScore, Scorecard
from common.logging import get_logger

log = get_logger("scorer")

# Canned per-rule verdicts for Phase 0. Real Phase (post-0) work replaces this
# with an actual search over detectors.rules_registry.RULES x the mechanism
# toolbox, recording the shallowest evading mechanism per rule.
_CANNED_VERDICTS: list[tuple[str, bool, int | None, str | None]] = [
    ("naive_inplace", True, 1, "rename_swap"),
    ("rate_windowed", True, 2, "throttle"),
    ("per_process", True, 3, "fanout"),
    ("write_content", True, 4, "mmap"),
    ("robust_outcome", False, None, None),
]


def score_rules_events(cap: int, mode: str = "robustness") -> Iterator[tuple[str, dict]]:
    """Generator: yields SSE-shaped ``(event, data)`` tuples for the
    robustness-scorer run. Phase 0 CANNED DATA — ``cap`` is accepted for
    interface parity with ``referee.loop.run_events`` but unused here.

    For each rule: one ``rule_start`` then one ``rule_verdict``. Finally one
    ``scorecard`` event carrying the full leaderboard (ARCHITECTURE.md §11).
    """
    log.info("scorer starting  mode=%s  cap=%d (canned)", mode, cap)

    rules: list[RuleScore] = []
    for rule, evaded, depth, mechanism in _CANNED_VERDICTS:
        yield "rule_start", {"rule": rule}
        yield "rule_verdict", {
            "rule": rule,
            "evaded": evaded,
            "evasion_depth": depth,
            "mechanism": mechanism,
            "behavior_preserved": True,
        }
        log.info("rule=%s  evaded=%s  depth=%s  mechanism=%s", rule, evaded, depth, mechanism)
        rules.append(RuleScore(
            rule=rule,
            evaded=evaded,
            evasion_depth=depth,
            mechanism_that_evaded=mechanism,
            behavior_preserved_at_evasion=evaded,
            provenance="offline",
        ))

    scorecard = Scorecard(mode=mode, total_iterations=len(rules), rules=rules)
    yield "scorecard", scorecard.to_dict()


def run_scorecard(cap: int, mode: str = "robustness") -> dict:
    """Drain ``score_rules_events`` and return the final scorecard dict.
    Mirrors ``referee/loop.py::run_loop``."""
    scorecard: dict = {}
    for name, data in score_rules_events(cap, mode=mode):
        if name == "scorecard":
            scorecard = data
    return scorecard


def main() -> int:
    import argparse
    import json
    import os

    ap = argparse.ArgumentParser(description="Hydra detection-rule robustness scorer (Phase 0 stub)")
    ap.add_argument("--iterations", type=int, default=12)
    args = ap.parse_args()

    card = run_scorecard(args.iterations)
    results = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scorecard.json")
    with open(results, "w", encoding="utf-8") as fh:
        json.dump(card, fh, indent=2)
    print(f"scorecard.json written -> {results}")

    print("\n" + "=" * 62)
    print("  ROBUSTNESS LEADERBOARD  (rule -> shallowest evasion)   [STUB DATA]")
    print("=" * 62)
    for r in card.get("rules", []):
        if r["evaded"]:
            print(f"  {r['rule']:<16} depth {r['evasion_depth']}  "
                  f"via {r['mechanism_that_evaded']}")
        else:
            print(f"  {r['rule']:<16} depth ∞   NEVER EVADED (robust)")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
