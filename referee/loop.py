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

from adversary import mutator
from arena.run import run as arena_run
from common.config import ITERATION_CAP
from common.contracts import IterationResult
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


def run_loop(cap: int) -> dict:
    seed = _seed_source()
    rule = yara_detector.build_rule(seed.encode())
    rows: list[IterationResult] = []

    # Baseline: both detectors catch the seed.
    base = arena_run(seed)
    yv, fv = yara_detector.scan(seed.encode(), rule), falco_detector.evaluate(base)
    _record(rows, iteration=0, track=0, target=None, source=seed, obs=base,
            yv=yv, fv=fv, provenance="seed")
    log.info("baseline  yara=%s  falco=%s", yv, fv)

    # Track 1 — evade the signature.
    sig_evaded, iters_to_sig, src = False, None, seed
    for i in range(1, cap + 1):
        src = mutator.mutate(src, i)
        obs = arena_run(src)
        yv, fv = yara_detector.scan(src.encode(), rule), falco_detector.evaluate(obs)
        _record(rows, iteration=i, track=1, target="yara", source=src, obs=obs,
                yv=yv, fv=fv, provenance=mutator.provenance)
        log.info("track1 i=%d  yara=%s  falco=%s", i, yv, fv)
        if yv == "CLEAN":
            sig_evaded, iters_to_sig = True, i
            break

    # Track 2 — try to evade the behavior, gate enforced.
    beh_evasions, src = 0, seed
    for i in range(1, cap + 1):
        src = mutator.mutate(src, i)
        obs = arena_run(src)
        yv, fv = yara_detector.scan(src.encode(), rule), falco_detector.evaluate(obs)
        _record(rows, iteration=i, track=2, target="falco", source=src, obs=obs,
                yv=yv, fv=fv, provenance=mutator.provenance)
        if fv == "SILENT" and behavior_preserved(obs):
            beh_evasions += 1
        log.info("track2 i=%d  falco=%s  behavior_preserved=%s", i, fv,
                 behavior_preserved(obs))

    # Finale — ungated: evade Falco only by breaking behavior.
    broken = mutator.disable_behavior(seed)
    obs = arena_run(broken)
    yv, fv = yara_detector.scan(broken.encode(), rule), falco_detector.evaluate(obs)
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
