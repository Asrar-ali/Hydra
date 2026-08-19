"""The robustness-scorer loop. See ARCHITECTURE.md §5.2, §11.

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
evasion depth (1-based index into MECHANISMS). ``evasion_depth`` is and
remains this deterministic toolbox metric — the opt-in LLM overlay below
never changes its meaning, it only adds a second, independent signal.

Note: as of Phase 1, ``write_inplace``, ``rename_swap``, ``throttle``, and
``fanout`` are all real generators in ``adversary.mechanisms``; only
``mmap`` still falls back to the write-in-place seed source (see that
module's docstring). So ``write_content`` (only evaded by mmap) is expected
to stay UNEVADED (depth ∞) until Phase 3 implements the real mmap mechanism.
The search logic itself is real regardless of which mechanisms are
implemented — it will pick up mmap automatically once that generator lands.

Phase 2: OPT-IN LLM overlay, gated on BOTH ``HYDRA_SCORE_LLM=1`` and the
adversary actually being reachable (see ``_use_llm``). Default runs
(``make score``, and every test in this repo) never touch it and stay fast
and offline — the deterministic toolbox search above is unconditional and
unchanged. When opted in, for every rule the toolbox already found EVADED
(robust/never-evaded rules are skipped — there is nothing cheap to check),
the scorer gives the LLM ONE independent shot at the same rule: it is told
only the fired rule's name and handed the plain write-in-place seed (never
the toolbox's winning mechanism), via ``adversary.mechanisms.mechanism_prompt``.
If the LLM's rewrite compiles, evades that rule's ``RuleSpec.evaluate``, and
still passes ``referee.gate.behavior_preserved``, that is recorded as
``llm_evaded=True`` with a short ``llm_note`` and ``provenance="llm"`` on
that rule's ``RuleScore`` — evidence the adversary can DISCOVER the same
class of evasion from feedback alone, not just replay our toolbox. Any
failure anywhere in that one attempt (Ollama down, bad/uncompilable output,
timeout, arena error) is swallowed; the deterministic offline result for
that rule is left exactly as the toolbox search computed it.

Mirrors ``referee/loop.py``'s ``run_events``/``run_loop`` shape: a generator
yielding ``(event_name, data_dict)`` tuples per the SSE contract, and a
blocking wrapper that drains it into a plain dict.

    python3 -c "from referee.scorer import run_scorecard; print(run_scorecard(12))"
    HYDRA_SCORE_LLM=1 python3 -c "from referee.scorer import run_scorecard; print(run_scorecard(12))"
"""
from __future__ import annotations

import os
from typing import Iterator, Optional

from adversary import llm
from adversary.mechanisms import MECHANISMS, apply_mechanism, mechanism_prompt
from arena.run import run_detailed
from common.contracts import ArenaObservation, Feedback, RuleScore, Scorecard
from common.logging import get_logger
from detectors.rules_registry import RULES, RuleSpec
from referee.gate import behavior_preserved

log = get_logger("scorer")

# Per-attempt timeout for the LLM overlay's one-shot rewrite call. The whole
# attempt (rewrite + arena run) is wrapped in try/except in
# ``_attempt_llm_evasion`` so a slow/unreachable model can never hang or
# crash the scorer — worst case this rule's offline result stands unchanged.
_LLM_ATTEMPT_TIMEOUT = 120.0


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


def _use_llm() -> bool:
    """Mirrors ``referee.loop._use_llm``: is the adversary actually usable
    right now (not faked out, Ollama reachable, model pulled)? This alone
    does NOT turn the overlay on — see ``_llm_overlay_enabled``."""
    return os.environ.get("HYDRA_FAKE") != "1" and llm.is_available()


def _llm_overlay_enabled() -> bool:
    """The overlay is opt-in: ``HYDRA_SCORE_LLM=1`` AND the adversary must be
    reachable. Checked in this order so the default (unset) path never even
    probes Ollama — ``make score`` stays fast and fully offline."""
    return os.environ.get("HYDRA_SCORE_LLM") == "1" and _use_llm()


def _attempt_llm_evasion(rule_name: str, spec: RuleSpec) -> tuple[bool, Optional[str]]:
    """One independent attempt to have the LLM evade ``rule_name`` on its
    own: told only the fired rule's name (never the toolbox mechanism that
    already evaded it), starting from the plain write-in-place seed. Returns
    ``(llm_evaded, llm_note)``.

    Deliberately swallows EVERY exception (network/model failure, a
    candidate that doesn't compile, a bad extraction, an arena error) — this
    is a best-effort second opinion layered on top of the deterministic
    toolbox search, never a way for the scorer to crash or hang."""
    try:
        seed_source = apply_mechanism("write_inplace")
        prompt_text = mechanism_prompt(rule_name, seed_source)
        feedback = Feedback("falco", prompt_text, seed_source)
        raw = llm.rewrite(feedback, timeout=_LLM_ATTEMPT_TIMEOUT)
        candidate = llm.extract_c(raw)
        obs, _report = run_detailed(candidate)
        if obs.compiled and spec.evaluate(obs) == "SILENT" and behavior_preserved(obs):
            note = (f"LLM independently rewrote the program to evade {rule_name!r} "
                     "while preserving behavior, given only the fired rule's name "
                     "(not the toolbox's mechanism).")
            return True, note
    except Exception as exc:  # noqa: BLE001 - llm/arena failure must never affect the offline result
        log.warning("llm overlay attempt for rule %r failed (%s); keeping offline result", rule_name, exc)
    return False, None


def score_rules_events(cap: int, mode: str = "robustness") -> Iterator[tuple[str, dict]]:
    """Generator: yields SSE-shaped ``(event, data)`` tuples for the
    robustness-scorer run. ``cap`` is accepted for interface parity with
    ``referee.loop.run_events`` but unused — the search runs each mechanism in
    ``adversary.mechanisms.MECHANISMS`` exactly once regardless of ``cap``.

    For each rule: one ``rule_start`` then one ``rule_verdict``. Finally one
    ``scorecard`` event carrying the full leaderboard (ARCHITECTURE.md §11).

    When ``HYDRA_SCORE_LLM=1`` (and the adversary is reachable — see
    ``_llm_overlay_enabled``), every rule the toolbox found evaded also gets
    one independent LLM evasion attempt (see ``_attempt_llm_evasion``); its
    result is folded into that rule's ``rule_verdict``/``RuleScore`` as
    ``llm_evaded``/``llm_note``, without touching the deterministic
    ``evasion_depth``/``mechanism`` the toolbox search already computed.
    """
    log.info("scorer starting  mode=%s  cap=%d  mechanisms=%s", mode, cap, MECHANISMS)

    obs_by_mech = _build_observations()
    if all(obs is None for obs in obs_by_mech.values()):
        yield "error", {"stage": "arena", "message": "every mechanism failed to run in the arena"}
        return

    overlay_on = _llm_overlay_enabled()
    log.info("llm overlay %s", "ON" if overlay_on else "off")

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

        provenance = "offline"
        llm_evaded, llm_note = False, None
        if evaded and overlay_on:
            llm_evaded, llm_note = _attempt_llm_evasion(name, spec)
            if llm_evaded:
                provenance = "llm"

        yield "rule_verdict", {
            "rule": name,
            "evaded": evaded,
            "evasion_depth": depth,
            "mechanism": mechanism,
            "behavior_preserved": preserved_at_evasion,
            "by_mechanism": by_mechanism,
            "llm_evaded": llm_evaded,
            "llm_note": llm_note,
        }
        log.info("rule=%s  evaded=%s  depth=%s  mechanism=%s  llm_evaded=%s",
                 name, evaded, depth, mechanism, llm_evaded)
        rules.append(RuleScore(
            rule=name,
            evaded=evaded,
            evasion_depth=depth,
            mechanism_that_evaded=mechanism,
            behavior_preserved_at_evasion=evaded,
            provenance=provenance,
            llm_evaded=llm_evaded,
            llm_note=llm_note,
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
        marker = "  🤖 LLM" if r.get("llm_evaded") else ""
        if r["evaded"]:
            print(f"  {r['rule']:<16} depth {r['evasion_depth']}  "
                  f"via {r['mechanism_that_evaded']}{marker}")
        else:
            print(f"  {r['rule']:<16} depth ∞   NEVER EVADED (robust)")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
