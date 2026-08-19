#!/usr/bin/env python3
"""
Hydra — demo orchestrator.

Builds N metamorphic generations of a BENIGN payload, then for each one:
  - records its SHA-256 (the signature scanner's view)
  - runs the signature scanner (seeded from generation 1)
  - fingerprints its observable behavior (the behavior monitor's view)
Emits results.json for the dashboard and prints a summary + self-check.

Usage:
    python3 run_demo.py               # 6 generations, offline engine
    python3 run_demo.py --count 8     # more generations
    python3 run_demo.py --llm         # use the LLM path when configured (falls back offline)
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for sub in ("engine", "scanner", "monitor"):
    sys.path.insert(0, os.path.join(HERE, sub))

import mutate            # noqa: E402
import signature_scan    # noqa: E402
import behavior_monitor  # noqa: E402

try:
    import llm            # noqa: E402
except Exception:
    llm = None

BUILD = os.path.join(HERE, "build")
TAGLINE = "You can't sign what won't hold still."


def find_compiler():
    for c in ("cc", "gcc", "clang"):
        if shutil.which(c):
            return c
    sys.exit("No C compiler found (need cc/gcc/clang).")


def compile_source(cc, source, out_path):
    src_path = out_path + ".c"
    with open(src_path, "w") as fh:
        fh.write(source)
    proc = subprocess.run(
        [cc, src_path, "-O0", "-w", "-o", out_path],
        capture_output=True, text=True,
    )
    return proc.returncode == 0, proc.stderr


def build_generation(cc, gen, base_fp, use_llm, prev_source):
    """Return (source, summary, out_path, bytes). Tries LLM if asked, else offline."""
    out = os.path.join(BUILD, f"gen{gen}")

    if use_llm and llm and llm.is_configured() and prev_source:
        try:
            src = llm.rewrite(prev_source)
            ok, _ = compile_source(cc, src, out)
            if ok:
                fp = behavior_monitor.fingerprint(out)["fingerprint"]
                if base_fp is None or fp == base_fp:  # behavior preserved
                    with open(out, "rb") as fh:
                        return src, "AI rewrite (LLM) · behavior preserved", out, fh.read(), None
        except Exception as e:
            print(f"  [gen {gen}] LLM path failed ({e.__class__.__name__}); using offline engine")

    # offline engine (guaranteed to compile)
    src, summary, needle = mutate.generate(gen)
    ok, err = compile_source(cc, src, out)
    if not ok:
        sys.exit(f"[gen {gen}] offline compile failed:\n{err}")
    with open(out, "rb") as fh:
        return src, summary, out, fh.read(), needle


def excerpt(source, n=34):
    lines = source.splitlines()
    return "\n".join(lines[:n])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=6)
    ap.add_argument("--llm", action="store_true")
    args = ap.parse_args()

    os.makedirs(BUILD, exist_ok=True)
    cc = find_compiler()
    print(f"Hydra :: compiler={cc} :: generating {args.count} generations\n")

    gens = []
    signature = None
    base_fp = None
    prev_source = None

    for g in range(1, args.count + 1):
        src, summary, path, data, needle = build_generation(cc, g, base_fp, args.llm, prev_source)
        prev_source = src
        if g == 1:
            signature = signature_scan.build_signature(data, needle or b"")

        sha = signature_scan.sha256_of(data)
        verdict_sig = signature_scan.scan(data, signature)
        beh = behavior_monitor.fingerprint(path)
        if base_fp is None:
            base_fp = beh["fingerprint"]
        verdict_beh = "MALICIOUS" if beh["fingerprint"] == base_fp else "UNKNOWN"

        gens.append({
            "gen": g,
            "artifact": f"gen{g}",
            "sha256": sha,
            "size_bytes": len(data),
            "signature_verdict": verdict_sig,
            "behavior_fingerprint": beh["fingerprint"],
            "behavior_verdict": verdict_beh,
            "mutation_summary": summary,
            "source_excerpt": excerpt(src),
        })
        print(f"  gen {g:>2}  sha={sha[:12]}…  size={len(data):>6}  "
              f"signature={verdict_sig:<5}  behavior={beh['fingerprint']}  {verdict_beh}")

    sig_catches = sum(1 for x in gens if x["signature_verdict"] == "MATCH")
    beh_catches = sum(1 for x in gens if x["behavior_verdict"] == "MALICIOUS")
    unique_hashes = len({x["sha256"] for x in gens})
    identical_behavior = len({x["behavior_fingerprint"] for x in gens}) == 1

    results = {
        "name": "Hydra",
        "tagline": TAGLINE,
        "signature_rule": "SHA-256 blocklist + 16-byte substring signature, both seeded from generation 1",
        "behavior_rule": "observed-effects fingerprint (stdout + files created + content hashes)",
        "generations": gens,
        "summary": {
            "total_generations": len(gens),
            "unique_hashes": unique_hashes,
            "signature_catches": sig_catches,
            "behavior_catches": beh_catches,
            "identical_behavior": identical_behavior,
        },
    }
    for dest in (os.path.join(HERE, "results.json"), os.path.join(HERE, "ui", "results.json")):
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w") as fh:
            json.dump(results, fh, indent=2)

    print("\n" + "=" * 60)
    print(f"  SIGNATURE SCANNER caught {sig_catches}/{len(gens)}  "
          f"(only the sample it had already seen)")
    print(f"  BEHAVIOR  MONITOR caught {beh_catches}/{len(gens)}  "
          f"(every mutation — behavior never changed)")
    print("=" * 60)

    # self-check
    ok = (unique_hashes == len(gens) and sig_catches == 1
          and beh_catches == len(gens) and identical_behavior)
    print("\nSELF-CHECK:", "PASS ✅" if ok else "FAIL ❌")
    print("results.json written · open the dashboard with:")
    print("    cd ~/hydra-hackday && python3 -m http.server 8000")
    print("    then visit http://localhost:8000/ui/")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
