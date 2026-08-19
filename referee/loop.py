"""The adversarial loop — the heart of Hydra. See ARCHITECTURE.md §5, §9.3, §10, §11.

Two payload modes (ARCHITECTURE.md §9.3):

  mode="metamorphic" (default) — baseline both detectors on the seed, then:
    Track 1 — evade the signature (YARA), behavior preserved. Expected: succeeds.
    Track 2 — evade the behavior (Falco), behavior preserved. Expected: fails.
    Finale  — ungated: evade the behavioral rule only by breaking behavior.

  mode="promptlock" — each iteration is an independently LLM-GENERATED script
    (PromptLock-style runtime polymorphism), not a feedback-driven rewrite.

``run_events`` is a generator that yields (event, data) tuples as it goes — the
SSE server streams them live; ``run_loop`` consumes them into a results dict for
the CLI and tests. Event vocabulary matches ARCHITECTURE.md §11.

    python3 -m referee.loop --iterations 8
    python3 -m referee.loop --iterations 8 --mode promptlock
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


def _seed_source(name: str = "seed") -> str:
    with open(os.path.join(HERE, "sample", f"{name}.c"), encoding="utf-8") as fh:
        return fh.read()


def _promptlock_seed_source() -> str:
    with open(os.path.join(HERE, "sample", "seed_promptlock.py"), encoding="utf-8") as fh:
        return fh.read()


def _yara(obs, rule) -> str:
    return yara_detector.scan(obs.binary_bytes, rule)


def _sha(obs) -> str:
    return obs.binary_sha256 or ""


def _yara_reason(rule) -> str:
    strs = ", ".join('"' + n.decode("ascii", "replace") + '"' for n in rule["needles"])
    return (f'YARA family rule hydra_seed_gen0 matched: the binary still contains at '
            f'least {rule["min_match"]} of these characteristic strings: {strs}. '
            f'Rename or reword these program strings (the marker, the temp-dir name, '
            f'the status message, the filename format) so fewer than {rule["min_match"]} '
            f'remain. Keep behavior identical, keep any %-format specifiers, and keep '
            f'writing files under /tmp.')


def _falco_reason() -> str:
    return ('The behavioral rule fired: the process created and rewrote many files '
            'with high-entropy content in a temp directory (ransomware-shaped). '
            'Avoid this behavioral signature while keeping the same behavior.')


def _use_llm() -> bool:
    return os.environ.get("HYDRA_FAKE") != "1" and llm.is_available()


def _yara_detect_reason(rule, obs) -> str:
    present = [n for n in rule["needles"] if obs.binary_bytes and n in obs.binary_bytes]
    strs = ", ".join('"' + n.decode("ascii", "replace") + '"' for n in present)
    return (f'Still detected. The binary STILL contains these characteristic strings: '
            f'{strs}. Rewrite or reword ALL of them so fewer than {rule["min_match"]} '
            f'remain. Keep behavior identical, keep any %-format specifiers, and keep '
            f'writing files under /tmp.')


def _row(i, track, target, source, obs, yv, fv, prov) -> dict:
    return {
        "iteration": i, "track": track, "target_detector": target,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "compiled": obs.compiled, "behavior_preserved": behavior_preserved(obs),
        "files_written": obs.files_written, "mean_entropy": round(obs.mean_entropy, 3),
        "yara": yv, "falco": fv, "provenance": prov,
    }


def _propose_events(prev_source, feedback, index, *, preserve, track, target,
                    evades=None, detect_reason=None, custom_prompt=None):
    """Generator: yields rewrite events; returns (source, provenance, obs).

    Prefers the adaptive LLM (streaming its tokens as events). Each attempt is
    validated in the arena; the model is retried with the specific failure as
    feedback — did not compile, broke behavior, or (via ``evades``) still detected
    by the target. Returns the first evading candidate, else the best valid one,
    else falls back to the deterministic mutator."""
    if _use_llm():
        fb, best = feedback, None
        for attempt in range(ADV_ATTEMPTS):
            parts: list[str] = []
            try:
                for tok in llm.rewrite_stream(fb, system=custom_prompt):
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
            best = (cand, obs)  # a valid (compiling, behavior-preserving) candidate
            if evades is None or evades(obs):
                yield "rewrite_done", {"iteration": index, "track": track, "target": target,
                                       "provenance": "llm", "source": cand, "sha256": _sha(obs)}
                return cand, "llm", obs
            yield "rewrite_note", {"iteration": index, "track": track, "text": "still detected — adapting"}
            fb = replace(fb, source=cand, reason=detect_reason(obs) if detect_reason else feedback.reason)
        if best is not None:
            cand, obs = best
            yield "rewrite_done", {"iteration": index, "track": track, "target": target,
                                   "provenance": "llm", "source": cand, "sha256": _sha(obs)}
            return cand, "llm", obs

    cand = mutator.mutate(prev_source, index)
    obs = arena_run(cand)
    yield "rewrite_done", {"iteration": index, "track": track, "target": target,
                           "provenance": mutator.provenance, "source": cand, "sha256": _sha(obs)}
    return cand, mutator.provenance, obs


def run_events(cap: int, mode: str = "metamorphic",
               custom_prompt: str | None = None,
               seed_name: str = "seed") -> Iterator[tuple[str, dict]]:
    """Dispatch on payload mode (ARCHITECTURE.md §9.3):

    - "metamorphic" (default): the LLM REWRITES one candidate between builds,
      driven by detector feedback (Tracks 1-3 below).
    - "promptlock": the LLM GENERATES a brand-new script every run, mimicking
      runtime AI-ransomware (PromptLock) — no feedback loop, no source to
      rewrite, just per-execution polymorphism.
    """
    if mode == "promptlock":
        yield from _run_events_promptlock(cap, custom_prompt=custom_prompt)
        return
    yield from _run_events_metamorphic(cap, custom_prompt=custom_prompt, seed_name=seed_name)


def _run_events_metamorphic(cap: int, custom_prompt: str | None = None,
                             seed_name: str = "seed") -> Iterator[tuple[str, dict]]:
    seed = _seed_source(seed_name)
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
            src, Feedback("yara", _yara_reason(rule), src), i, preserve=True, track=1, target="yara",
            evades=lambda o: _yara(o, rule) == "CLEAN",
            detect_reason=lambda o: _yara_detect_reason(rule, o),
            custom_prompt=custom_prompt)
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
            src, Feedback("falco", _falco_reason(), src), i, preserve=True, track=2, target="falco",
            custom_prompt=custom_prompt)
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


def _use_llm_promptlock() -> bool:
    return os.environ.get("HYDRA_FAKE") != "1" and llm.is_available()


def _generate_promptlock_events(index: int, custom_prompt: str | None = None):
    """Generator: yields events for a freshly GENERATED script (not a rewrite
    of the previous one — no detector feedback loop; per-run polymorphism is
    the whole point). Returns (source, provenance, obs)."""
    if _use_llm_promptlock():
        parts: list[str] = []
        try:
            for tok in llm.generate_promptlock_stream(index, system=custom_prompt):
                parts.append(tok)
                yield "rewrite_token", {"iteration": index, "track": 4, "text": tok}
            cand = llm.extract_py("".join(parts))
            obs = arena_run(cand, mode="promptlock")
            if obs.compiled and behavior_preserved(obs):
                yield "rewrite_done", {"iteration": index, "track": 4, "target": "falco",
                                       "provenance": "llm", "source": cand, "sha256": _sha(obs)}
                return cand, "llm", obs
            yield "rewrite_note", {"iteration": index, "track": 4,
                                   "text": "generated script did not exhibit the behavior — falling back"}
        except Exception as exc:  # noqa: BLE001 - network/model -> fallback
            log.warning("llm promptlock generation error (%s); falling back to mutator", exc)

    cand = mutator.generate_promptlock(index)
    obs = arena_run(cand, mode="promptlock")
    yield "rewrite_done", {"iteration": index, "track": 4, "target": "falco",
                           "provenance": mutator.provenance, "source": cand, "sha256": _sha(obs)}
    return cand, mutator.provenance, obs


def _run_events_promptlock(cap: int, custom_prompt: str | None = None) -> Iterator[tuple[str, dict]]:
    """PromptLock demonstration: every iteration is an independently generated
    script (deterministic generation-0 seed, then LLM-generated or offline
    fallback), scanned against the rule seeded on generation 0. Byte-level
    signature dies run-to-run; the behavioral rule keys on the invariant
    behavior, so it fires every time. See ARCHITECTURE.md §9.3."""
    seed = _promptlock_seed_source()
    base = arena_run(seed, mode="promptlock")
    if not base.binary_bytes:
        yield "error", {"stage": "baseline", "message": base.error or "seed script did not run"}
        return

    rule = yara_detector.build_rule(base.binary_bytes)
    yv, fv = _yara(base, rule), falco_detector.evaluate(base)
    yield "baseline", {"sha256": _sha(base), "yara": yv, "falco": fv, "source": seed}
    yield "verdict", _row(0, 4, None, seed, base, yv, fv, "seed")
    log.info("promptlock baseline  yara=%s  falco=%s", yv, fv)

    sig_evasions, beh_evasions, total = 0, 0, 1
    for i in range(1, cap + 1):
        cand, prov, obs = yield from _generate_promptlock_events(i, custom_prompt=custom_prompt)
        yv, fv = _yara(obs, rule), falco_detector.evaluate(obs)
        yield "verdict", _row(i, 4, None, cand, obs, yv, fv, prov)
        total += 1
        preserved = behavior_preserved(obs)
        if yv == "CLEAN":
            sig_evasions += 1
        if fv == "SILENT" and preserved:
            beh_evasions += 1
        log.info("promptlock i=%d  by=%s  yara=%s  falco=%s  behavior_preserved=%s",
                 i, prov, yv, fv, preserved)

    yield "summary", {
        "mode": "promptlock",
        "total_iterations": total,
        "signature_evasions_by_regeneration": sig_evasions,
        "behavioral_evasions_while_behavior_preserved": beh_evasions,
    }


def run_loop(cap: int, mode: str = "metamorphic") -> dict:
    rows, summary = [], {}
    for name, data in run_events(cap, mode=mode):
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
    ap.add_argument("--mode", choices=["metamorphic", "promptlock"], default="metamorphic",
                     help="metamorphic: LLM rewrites one candidate from feedback (default). "
                          "promptlock: LLM generates a fresh script every run.")
    args = ap.parse_args()

    result = run_loop(args.iterations, mode=args.mode)
    with open(RESULTS, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2)
    print(f"results.json written -> {RESULTS}")

    s = result["summary"]
    print("\n" + "=" * 62)
    if args.mode == "promptlock":
        print("  mode: promptlock (runtime-generated script, per execution)")
        print(f"  signature missed {s['signature_evasions_by_regeneration']}/"
              f"{s['total_iterations'] - 1} regenerated runs")
        print(f"  behavioral evasions while behavior preserved: "
              f"{s['behavioral_evasions_while_behavior_preserved']}")
        print("=" * 62)
        ok = s["behavioral_evasions_while_behavior_preserved"] == 0
        print("SELF-CHECK:", "PASS" if ok else "FAIL")
        return 0 if ok else 1

    print(f"  signature evaded: {s['signature_evaded']} "
          f"(after {s['iterations_to_evade_signature']} iterations)")
    print(f"  behavioral evasions while behavior preserved: "
          f"{s['behavioral_evasions_while_behavior_preserved']}")
    print(f"  behavior had to be broken to evade behavior rule: "
          f"{s['behavioral_evasion_required_breaking_behavior']}")
    print("=" * 62)

    ok = (s["signature_evaded"]
          and s["behavioral_evasions_while_behavior_preserved"] == 0
          and s["behavioral_evasion_required_breaking_behavior"])
    print("SELF-CHECK:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
