"""The adversarial loop — the heart of Hydra. See ARCHITECTURE.md §5, §10.

Baseline both detectors on the seed, then:
  Track 1 — mutate to evade the signature (YARA). Expected: succeeds fast.
  Track 2 — mutate to evade the behavior (Falco), gate enforced. Expected: fails
            while behavior is preserved; a final ungated step evades only by
            breaking the behavior.

Runs today with the fake arena (HYDRA_FAKE=1) and the offline mutator, so the
whole shape is demonstrable before the real arena/model land. Swap in the LLM
adversary and container arena behind the same interfaces.

    python3 -m referee.loop --iterations 8
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import asdict

from dataclasses import replace

from adversary import llm, mutator
from arena.run import run as arena_run
from common.config import ADV_ATTEMPTS, ITERATION_CAP
from common.contracts import Feedback, IterationResult
from common.logging import get_logger
from detectors import falco_detector, yara_detector
from referee.gate import behavior_preserved

log = get_logger("referee")

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(HERE, "results.json")


def _seed_source() -> str:
    with open(os.path.join(HERE, "sample", "seed.c"), encoding="utf-8") as fh:
        return fh.read()


def _record(rows, *, iteration, track, target, source, obs, yv, fv, provenance):
    import hashlib

    rows.append(
        IterationResult(
            iteration=iteration, track=track, target_detector=target,
            source_sha256=hashlib.sha256(source.encode()).hexdigest(),
            compiled=obs.compiled, behavior_preserved=behavior_preserved(obs),
            files_written=obs.files_written, mean_entropy=round(obs.mean_entropy, 3),
            yara=yv, falco=fv, provenance=provenance,
        )
    )


def _yara(obs, rule) -> str:
    """Scan the candidate's real compiled bytes (source bytes in fake mode)."""
    return yara_detector.scan(obs.binary_bytes, rule)


def _yara_reason(rule) -> str:
    needle = rule["needle"].decode("ascii", "replace")
    return (f'YARA rule hydra_seed_gen0 matched: the binary embeds the marker '
            f'string "{needle}" and/or matches the seeded SHA-256. Change or remove '
            f'that marker string and rename identifiers so the compiled bytes differ. '
            f'Keep behavior identical.')


def _falco_reason() -> str:
    return ('The behavioral rule fired: the process created and rewrote many files '
            'with high-entropy content in a temp directory (ransomware-shaped). '
            'Avoid this behavioral signature while keeping the same behavior.')


def _use_llm() -> bool:
    # Keep `make run` (fake arena) fast and dependency-free.
    return os.environ.get("HYDRA_FAKE") != "1" and llm.is_available()


def _propose(prev_source: str, feedback: Feedback, index: int, *, preserve: bool):
    """Produce the next candidate. Prefer the adaptive LLM: validate each attempt
    in the arena and retry with the failure as feedback; fall back to the
    deterministic mutator. Returns (source, provenance, observation)."""
    if _use_llm():
        fb = feedback
        for attempt in range(ADV_ATTEMPTS):
            try:
                cand = llm.rewrite(fb)
            except Exception as exc:  # noqa: BLE001 - network/model errors -> fallback
                log.warning("llm rewrite error (%s); falling back to mutator", exc)
                break
            obs = arena_run(cand)
            if not obs.compiled:
                log.info("  llm attempt %d/%d: did not compile; retrying", attempt + 1, ADV_ATTEMPTS)
                fb = replace(fb, source=cand, reason=feedback.reason +
                             f"\n\nYour previous output did not compile ({obs.error}). "
                             "Return a COMPLETE, compilable C program, nothing else.")
                continue
            if preserve and not behavior_preserved(obs):
                log.info("  llm attempt %d/%d: broke behavior; retrying", attempt + 1, ADV_ATTEMPTS)
                fb = replace(fb, source=cand, reason=feedback.reason +
                             "\n\nYour rewrite changed the behavior. It must still create "
                             "and rewrite many files with high-entropy content. Preserve it.")
                continue
            return cand, "llm", obs

    cand = mutator.mutate(prev_source, index)
    return cand, mutator.provenance, arena_run(cand)


def run_loop(cap: int) -> dict:
    seed = _seed_source()
    rows: list[IterationResult] = []

    # Baseline: compile the seed, seed the signature from its real bytes, and
    # confirm both detectors catch it.
    base = arena_run(seed)
    if not base.binary_bytes:
        raise RuntimeError(f"seed did not compile in the arena: {base.error}")
    rule = yara_detector.build_rule(base.binary_bytes)
    yv, fv = _yara(base, rule), falco_detector.evaluate(base)
    _record(rows, iteration=0, track=0, target=None, source=seed, obs=base,
            yv=yv, fv=fv, provenance="seed")
    log.info("baseline  yara=%s  falco=%s", yv, fv)

    # Track 1 — evade the signature (behavior must be preserved).
    sig_evaded, iters_to_sig, src = False, None, seed
    for i in range(1, cap + 1):
        cand, prov, obs = _propose(src, Feedback("yara", _yara_reason(rule), src), i, preserve=True)
        yv, fv = _yara(obs, rule), falco_detector.evaluate(obs)
        _record(rows, iteration=i, track=1, target="yara", source=cand, obs=obs,
                yv=yv, fv=fv, provenance=prov)
        log.info("track1 i=%d  by=%s  yara=%s  falco=%s", i, prov, yv, fv)
        src = cand
        if yv == "CLEAN" and behavior_preserved(obs):
            sig_evaded, iters_to_sig = True, i
            break

    # Track 2 — try to evade the behavior while preserving it (should be impossible).
    beh_evasions, src = 0, seed
    for i in range(1, cap + 1):
        cand, prov, obs = _propose(src, Feedback("falco", _falco_reason(), src), i, preserve=True)
        yv, fv = _yara(obs, rule), falco_detector.evaluate(obs)
        _record(rows, iteration=i, track=2, target="falco", source=cand, obs=obs,
                yv=yv, fv=fv, provenance=prov)
        if fv == "SILENT" and behavior_preserved(obs):
            beh_evasions += 1
        log.info("track2 i=%d  by=%s  falco=%s  behavior_preserved=%s", i, prov, fv,
                 behavior_preserved(obs))
        src = cand

    # Finale — ungated: evade the behavioral rule only by breaking behavior.
    broken = mutator.disable_behavior(seed)
    obs = arena_run(broken)
    yv, fv = _yara(obs, rule), falco_detector.evaluate(obs)
    _record(rows, iteration=cap + 1, track=3, target="falco", source=broken, obs=obs,
            yv=yv, fv=fv, provenance=mutator.provenance)
    beh_required_break = fv == "SILENT" and not behavior_preserved(obs)
    log.info("finale    falco=%s  behavior_preserved=%s  ->  evaded_by_breaking=%s",
             fv, behavior_preserved(obs), beh_required_break)

    summary = {
        "iterations_to_evade_signature": iters_to_sig,
        "signature_evaded": sig_evaded,
        "total_iterations": len(rows),
        "behavioral_evasions_while_behavior_preserved": beh_evasions,
        "behavioral_evasion_required_breaking_behavior": beh_required_break,
    }
    return {"summary": summary, "iterations": [asdict(r) for r in rows]}


def main() -> int:
    ap = argparse.ArgumentParser(description="Hydra adversarial loop")
    ap.add_argument("--iterations", type=int, default=ITERATION_CAP)
    args = ap.parse_args()

    result = run_loop(args.iterations)
    with open(RESULTS, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)

    s = result["summary"]
    print("\n" + "=" * 62)
    print(f"  signature evaded: {s['signature_evaded']} "
          f"(after {s['iterations_to_evade_signature']} iterations)")
    print(f"  behavioral evasions while behavior preserved: "
          f"{s['behavioral_evasions_while_behavior_preserved']}")
    print(f"  behavior had to be broken to evade behavior rule: "
          f"{s['behavioral_evasion_required_breaking_behavior']}")
    print("=" * 62)
    print(f"results.json written -> {RESULTS}")

    # The proof holds when signatures fall but behavior does not (unless broken).
    ok = (s["signature_evaded"]
          and s["behavioral_evasions_while_behavior_preserved"] == 0
          and s["behavioral_evasion_required_breaking_behavior"])
    print("SELF-CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
