"""The robustness-scorer loop. See ARCHITECTURE.md §11.

Drives Hydra's "detection-rule robustness scorer" mode: for each behavioral
rule in ``detectors/rules_registry.RULES`` (naive_inplace, rate_windowed,
per_process, write_content, robust_outcome), search the mechanism toolbox
(adversary/) for the shallowest mechanism that evades it while behavior is
preserved, and record that evasion depth. The result is a leaderboard —
which rules are robust (never evaded) and which fall to a cheap mechanism.

Phase 1: REAL search. Each mechanism in ``adversary.mechanisms.MECHANISMS`` is
run through the arena exactly ONCE (``arena.run.run_detailed``) and the
resulting ``ArenaObservation`` is cached; every rule is then evaluated against
those cached observations. That's ``len(MECHANISMS)`` arena runs total (5),
not one per rule x mechanism pair (25). For each rule, the mechanisms are
walked in ``MECHANISMS`` order (weakest evasion first — shallowest depth
wins) and the first one that drives the rule SILENT while
``referee.gate.behavior_preserved`` is still True is recorded as that rule's
evasion depth (1-based index into MECHANISMS).

Note: as of Phase 1, ``write_inplace``, ``rename_swap``, ``throttle``, and
``fanout`` are all real generators in ``adversary.mechanisms``; only
``mmap`` still falls back to the write-in-place seed source (see that
module's docstring). So ``write_content`` (only evaded by mmap) is expected
to stay UNEVADED (depth ∞) until Phase 3 implements the real mmap mechanism.
The search logic itself is real regardless of which mechanisms are
implemented — it will pick up mmap automatically once that generator lands.

Mirrors ``referee/loop.py``'s ``run_events``/``run_loop`` shape: a generator
yielding ``(event_name, data_dict)`` tuples per the SSE contract, and a
blocking wrapper that drains it into a plain dict.

    python3 -c "from referee.scorer import run_scorecard; print(run_scorecard(12))"
"""
from __future__ import annotations

from typing import Iterator, Optional

from adversary.mechanisms import MECHANISMS, apply_mechanism
from arena.run import run_detailed
from common.contracts import ArenaObservation, RuleScore, Scorecard
from common.logging import get_logger
from detectors.rules_registry import RULES
from referee.gate import behavior_preserved

log = get_logger("scorer")


def _build_observations() -> dict[str, Optional[ArenaObservation]]:
    """Run every mechanism through the arena exactly once and cache its
    ArenaObservation, keyed by mechanism name. A mechanism whose arena run
    raises (e.g. Docker missing) maps to None rather than crashing the whole
    search — callers must skip None entries when walking MECHANISMS for a
    rule's evasion search."""
    obs_by_mech: dict[str, Optional[ArenaObservation]] = {}
    for m in MECHANISMS:
        try:
            source = apply_mechanism(m)
            obs, _report = run_detailed(source)
            obs_by_mech[m] = obs
        except Exception as exc:  # noqa: BLE001 - arena/docker failure -> skip this mechanism
            log.warning("mechanism %r failed to run in the arena (%s); skipping it in the search", m, exc)
            obs_by_mech[m] = None
    return obs_by_mech


def score_rules_events(cap: int, mode: str = "robustness") -> Iterator[tuple[str, dict]]:
    """Generator: yields SSE-shaped ``(event, data)`` tuples for the
    robustness-scorer run. ``cap`` is accepted for interface parity with
    ``referee.loop.run_events`` but unused — the search runs each mechanism in
    ``adversary.mechanisms.MECHANISMS`` exactly once regardless of ``cap``.

    For each rule: one ``rule_start`` then one ``rule_verdict``. Finally one
    ``scorecard`` event carrying the full leaderboard (ARCHITECTURE.md §11).
    """
    log.info("scorer starting  mode=%s  cap=%d  mechanisms=%s", mode, cap, MECHANISMS)

    obs_by_mech = _build_observations()
    if all(obs is None for obs in obs_by_mech.values()):
        yield "error", {"stage": "arena", "message": "every mechanism failed to run in the arena"}
        return

    rules: list[RuleScore] = []
    for name, spec in RULES.items():
        yield "rule_start", {"rule": name}

        evaded, depth, mechanism, preserved_at_evasion = False, None, None, False
        for i, m in enumerate(MECHANISMS, start=1):
            obs = obs_by_mech[m]
            if obs is None:
                continue
            if spec.evaluate(obs) == "SILENT" and behavior_preserved(obs):
                evaded, depth, mechanism, preserved_at_evasion = True, i, m, True
                break

        by_mechanism = {m: spec.evaluate(obs) for m, obs in obs_by_mech.items() if obs is not None}

        yield "rule_verdict", {
            "rule": name,
            "evaded": evaded,
            "evasion_depth": depth,
            "mechanism": mechanism,
            "behavior_preserved": preserved_at_evasion,
            "by_mechanism": by_mechanism,
        }
        log.info("rule=%s  evaded=%s  depth=%s  mechanism=%s", name, evaded, depth, mechanism)
        rules.append(RuleScore(
            rule=name,
            evaded=evaded,
            evasion_depth=depth,
            mechanism_that_evaded=mechanism,
            behavior_preserved_at_evasion=evaded,
            provenance="offline",
        ))

    scorecard = Scorecard(mode=mode, total_iterations=len(MECHANISMS), rules=rules)
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

    ap = argparse.ArgumentParser(description="Hydra detection-rule robustness scorer")
    ap.add_argument("--iterations", type=int, default=12)
    args = ap.parse_args()

    card = run_scorecard(args.iterations)
    results = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scorecard.json")
    with open(results, "w", encoding="utf-8") as fh:
        json.dump(card, fh, indent=2)
    print(f"scorecard.json written -> {results}")

    print("\n" + "=" * 62)
    print("  ROBUSTNESS LEADERBOARD  (rule -> shallowest evasion)")
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
