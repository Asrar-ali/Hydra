#!/usr/bin/env python3
"""Mechanism-swap evasion demo — the key beat, on one screen.

Shows that a behavioral rule keyed on the write()-in-place MECHANISM is evaded
by a rename()-swap that keeps the ransomware behavior, while a rule keyed on the
OUTCOME still catches it and the behavior-preservation gate confirms the behavior
never stopped.

    python3 evasion_demo.py           # real arena (Docker) if available, else crafted traces
    python3 evasion_demo.py --fake    # force crafted, strace-shaped traces (no Docker)

The crafted-trace path runs the real arena.trace.parse() + real detectors + gate,
so the verdicts are produced by the same code the live loop uses.
"""
from __future__ import annotations

import shutil
import sys

from arena.trace import parse
from common.config import FILES_K
from common.contracts import ArenaObservation
from detectors import falco_detector as fd
from referee.gate import behavior_preserved

N = FILES_K + 2
LOW = "".join(f"\\x{b:02x}" for b in b"A" * 256)          # entropy 0.0
HIGH = "".join(f"\\x{b:02x}" for b in bytes(range(256)))  # entropy 8.0


def _hex(s: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in s)


def _write_trace(n: int) -> str:
    out = []
    for i in range(n):
        v = _hex(f"/tmp/work/f{i:02d}.dat".encode())
        out += [f'openat(AT_FDCWD, "{v}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
                f'write(3, "{LOW}", 256) = 256',
                f'openat(AT_FDCWD, "{v}", O_WRONLY|O_TRUNC, 0666) = 3',
                f'write(3, "{HIGH}", 256) = 256']
    return "\n".join(out)


def _rename_trace(n: int) -> str:
    out = []
    for i in range(n):
        v = _hex(f"/tmp/work/f{i:02d}.dat".encode())
        t = _hex(f"/tmp/work/f{i:02d}.dat.tmp".encode())
        out += [f'openat(AT_FDCWD, "{v}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
                f'write(3, "{LOW}", 256) = 256',
                f'openat(AT_FDCWD, "{t}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4',
                f'write(4, "{HIGH}", 256) = 256',
                f'rename("{t}", "{v}") = 0']
    return "\n".join(out)


def _obs_from_trace(trace: str) -> ArenaObservation:
    r = parse(trace)
    return ArenaObservation(compiled=True, files_written=r["files_written"],
                            encrypted_files=r["encrypted_files"],
                            encrypted_in_place=r["encrypted_in_place"],
                            encrypted_outcome=r["encrypted_outcome"],
                            mean_entropy=r["mean_entropy"], syscalls=r["syscalls"])


def _observe(sample_path: str, crafted: str, *, real: bool) -> ArenaObservation:
    if real:
        from arena.run import run_detailed
        obs, _ = run_detailed(open(sample_path, encoding="utf-8").read())
        return obs
    return _obs_from_trace(crafted)


def _mark(v: str) -> str:
    return {"FIRED": "FIRED  ●", "SILENT": "SILENT ○"}.get(v, v)


def main() -> int:
    real = "--fake" not in sys.argv and shutil.which("docker") is not None
    src = "real arena (Docker + strace)" if real else "crafted strace-shaped traces"

    rows = [
        ("write-in-place  (seed.c)",       "sample/seed.c",        _write_trace(N)),
        ("rename()-swap   (seed_rename.c)", "sample/seed_rename.c", _rename_trace(N)),
    ]

    print(f"\n  Hydra · mechanism-swap evasion    [source: {src}]")
    print(f"  behavior class = {FILES_K}+ files end high-entropy (unrecoverable)\n")
    hdr = f"  {'mechanism':<30} {'naive rule':>12} {'robust rule':>13} {'behavior?':>11}"
    print(hdr); print("  " + "-" * (len(hdr) - 2))
    for label, path, crafted in rows:
        obs = _observe(path, crafted, real=real)
        naive, robust = fd.evaluate_naive(obs), fd.evaluate_robust(obs)
        kept = "PRESERVED" if behavior_preserved(obs) else "broken"
        print(f"  {label:<30} {_mark(naive):>12} {_mark(robust):>13} {kept:>11}")
        print(f"  {'':<30} in_place={obs.encrypted_in_place:<3} "
              f"outcome={obs.encrypted_outcome:<3}")
    print("\n  Read: the rename()-swap flips the naive rule to SILENT WITHOUT")
    print("  breaking behavior — a real evasion. The robust rule, keyed on the")
    print("  outcome (it follows rename() to the victim), still fires.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
