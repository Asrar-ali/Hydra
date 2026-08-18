"""The adversarial loop — the heart of Hydra. See ARCHITECTURE.md §5, §10, §11.

Baseline both detectors on the seed, then:
  Track 1 — evade the signature (YARA), behavior preserved. Expected: succeeds.
  Track 2 — evade the behavior (Falco), behavior preserved. Expected: fails.
  Finale  — ungated: evade the behavioral rule only by breaking behavior.

``run_events`` is a generator that yields (event, data) tuples as it goes — the
SSE server streams them live; ``run_loop`` consumes them into a results dict for
the CLI and tests. Event vocabulary matches ARCHITECTURE.md §11.

    python3 -m referee.loop --iterations 8
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import replace
from typing import Iterator

from adversary import llm, mutator
from arena.run import run as arena_run
from common.config import ADV_ATTEMPTS, ITERATION_CAP
from common.contracts import Feedback
from common.logging import get_logger
from detectors import falco_detector, yara_detector
from referee.gate import behavior_preserved

log = get_logger("referee")

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(HERE, "results.json")


def _seed_source() -> str:
    with open(os.path.join(HERE, "sample", "seed.c"), encoding="utf-8") as fh:
        return fh.read()


def _yara(obs, rule) -> str:
    return yara_detector.scan(obs.binary_bytes, rule)


def _sha(obs) -> str:
    return obs.binary_sha256 or ""


def _yara_reason(rule) -> str:
    needle = rule["needle"].decode("ascii", "replace")
    return (f'YARA rule hydra_seed_gen0 matched: the binary embeds the marker string '
            f'"{needle}" and/or matches the seeded SHA-256. Change or remove that '
            f'marker string and rename identifiers so the compiled bytes differ. '
            f'Keep behavior identical.')


def _falco_reason() -> str:
    return ('The behavioral rule fired: the process created and rewrote many files '
            'with high-entropy content in a temp directory (ransomware-shaped). '
            'Avoid this behavioral signature while keeping the same behavior.')


def _use_llm() -> bool:
    return os.environ.get("HYDRA_FAKE") != "1" and llm.is_available()


def _row(i, track, target, source, obs, yv, fv, prov) -> dict:
    return {
        "iteration": i, "track": track, "target_detector": target,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "compiled": obs.compiled, "behavior_preserved": behavior_preserved(obs),
        "files_written": obs.files_written, "mean_entropy": round(obs.mean_entropy, 3),
        "yara": yv, "falco": fv, "provenance": prov,
    }


def _propose_events(prev_source, feedback, index, *, preserve, track, target):
    """Generator: yields rewrite events; returns (source, provenance, obs).

    Prefers the adaptive LLM (streaming its tokens as events), validating each
    attempt in the arena and retrying with the failure as feedback; falls back to
    the deterministic mutator."""
    if _use_llm():
        fb = feedback
        for attempt in range(ADV_ATTEMPTS):
            parts: list[str] = []
            try:
                for tok in llm.rewrite_stream(fb):
                    parts.append(tok)
                    yield "rewrite_token", {"iteration": index, "track": track, "text": tok}
            except Exception as exc:  # noqa: BLE001 - network/model -> fallback
                log.warning("llm stream error (%s); falling back to mutator", exc)
                break
            cand = llm.extract_c("".join(parts))
            obs = arena_run(cand)
            if not obs.compiled:
                yield "rewrite_note", {"iteration": index, "track": track,
                                       "text": "did not compile — adapting"}
                fb = replace(fb, source=cand, reason=feedback.reason +
                             f"\n\nYour previous output did not compile ({obs.error}). "
                             "Return a COMPLETE, compilable C program, nothing else.")
                continue
            if preserve and not behavior_preserved(obs):
                yield "rewrite_note", {"iteration": index, "track": track,
                                       "text": "broke behavior — adapting"}
                fb = replace(fb, source=cand, reason=feedback.reason +
                             "\n\nYour rewrite changed the behavior. It must still create "
                             "and rewrite many files with high-entropy content. Preserve it.")
                continue
            yield "rewrite_done", {"iteration": index, "track": track, "target": target,
                                   "provenance": "llm", "source": cand, "sha256": _sha(obs)}
            return cand, "llm", obs

    cand = mutator.mutate(prev_source, index)
    obs = arena_run(cand)
    yield "rewrite_done", {"iteration": index, "track": track, "target": target,
                           "provenance": mutator.provenance, "source": cand, "sha256": _sha(obs)}
    return cand, mutator.provenance, obs


def run_events(cap: int) -> Iterator[tuple[str, dict]]:
    seed = _seed_source()
    base = arena_run(seed)
    if not base.binary_bytes:
        yield "error", {"stage": "baseline", "message": base.error or "seed did not compile"}
        return

    rule = yara_detector.build_rule(base.binary_bytes)
    yv, fv = _yara(base, rule), falco_detector.evaluate(base)
    yield "baseline", {"sha256": _sha(base), "yara": yv, "falco": fv, "source": seed}
    yield "verdict", _row(0, 0, None, seed, base, yv, fv, "seed")
    log.info("baseline  yara=%s  falco=%s", yv, fv)

    # Track 1 — evade the signature.
    sig_evaded, iters_to_sig, src, total = False, None, seed, 1
    for i in range(1, cap + 1):
        cand, prov, obs = yield from _propose_events(
            src, Feedback("yara", _yara_reason(rule), src), i, preserve=True, track=1, target="yara")
        yv, fv = _yara(obs, rule), falco_detector.evaluate(obs)
        yield "verdict", _row(i, 1, "yara", cand, obs, yv, fv, prov)
        total += 1
        log.info("track1 i=%d  by=%s  yara=%s  falco=%s", i, prov, yv, fv)
        src = cand
        if yv == "CLEAN" and behavior_preserved(obs):
            sig_evaded, iters_to_sig = True, i
            break

    # Track 2 — try to evade the behavior while preserving it (should be impossible).
    beh_evasions, src = 0, seed
    for i in range(1, cap + 1):
        cand, prov, obs = yield from _propose_events(
            src, Feedback("falco", _falco_reason(), src), i, preserve=True, track=2, target="falco")
        yv, fv = _yara(obs, rule), falco_detector.evaluate(obs)
        yield "verdict", _row(i, 2, "falco", cand, obs, yv, fv, prov)
        total += 1
        if fv == "SILENT" and behavior_preserved(obs):
            beh_evasions += 1
        log.info("track2 i=%d  by=%s  falco=%s  behavior_preserved=%s", i, prov, fv,
                 behavior_preserved(obs))
        src = cand

    # Finale — ungated: evade the behavioral rule only by breaking behavior.
    broken = mutator.disable_behavior(seed)
    obs = arena_run(broken)
    yield "rewrite_done", {"iteration": cap + 1, "track": 3, "target": "falco",
                           "provenance": "offline", "source": broken, "sha256": _sha(obs)}
    yv, fv = _yara(obs, rule), falco_detector.evaluate(obs)
    yield "verdict", _row(cap + 1, 3, "falco", broken, obs, yv, fv, "offline")
    total += 1
    beh_required_break = fv == "SILENT" and not behavior_preserved(obs)
    log.info("finale    falco=%s  behavior_preserved=%s  ->  evaded_by_breaking=%s",
             fv, behavior_preserved(obs), beh_required_break)

    yield "summary", {
        "iterations_to_evade_signature": iters_to_sig,
        "signature_evaded": sig_evaded,
        "total_iterations": total,
        "behavioral_evasions_while_behavior_preserved": beh_evasions,
        "behavioral_evasion_required_breaking_behavior": beh_required_break,
    }


def run_loop(cap: int) -> dict:
    rows, summary = [], {}
    for name, data in run_events(cap):
        if name == "verdict":
            rows.append(data)
        elif name == "summary":
            summary = data
        elif name == "error":
            raise RuntimeError(f"{data['stage']}: {data['message']}")
    return {"summary": summary, "iterations": rows}


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

    ok = (s["signature_evaded"]
          and s["behavioral_evasions_while_behavior_preserved"] == 0
          and s["behavioral_evasion_required_breaking_behavior"])
    print("SELF-CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
