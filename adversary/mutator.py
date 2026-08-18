"""Deterministic mutator — the Track-1 fallback when the LLM is unavailable.

It cannot *adapt* (that is the LLM's job), but it can produce byte-different,
behavior-identical variants: enough to evade a signature. It also provides a
``disable_behavior`` helper used only for the finale (§5, Track 2 ungated step).

Promptlock mode (ARCHITECTURE.md §9.3) has no source to rewrite — each run is a
fresh generation — so its fallback is ``generate_promptlock``, a deterministic
Python-script assembler that still varies names/prefixes/keys per iteration.

Contract:
    mutate(source: str, iteration: int) -> str
    disable_behavior(source: str) -> str
    generate_promptlock(iteration: int) -> str
"""
from __future__ import annotations

import re

from arena.run import BEHAVIOR_DISABLED_MARK
from common.contracts import Provenance
from common.logging import get_logger

log = get_logger("mutator")

provenance: Provenance = "offline"

_MARKER = re.compile(r'"HYDRA-SIGNATURE-\d{3}"')


def mutate(source: str, iteration: int) -> str:
    """Rewrite the characteristic strings the family signature keys on — the
    marker, the temp-dir name, the status message, the filename format — so fewer
    than the rule's threshold remain, while preserving behavior (format specifiers
    and the /tmp sandbox are kept). Deterministic fallback for the LLM."""
    h = f"{(iteration * 2654435761) & 0xFFFF:04x}"
    s = _MARKER.sub(f'"MK{h}-{iteration:03d}"', source)          # marker
    s = s.replace("hydra_work", f"wk{h}")                        # temp-dir name (keeps /tmp + _XXXXXX)
    s = s.replace("reversible, exiting clean", f"ok {h} done")   # status message
    s = s.replace("file_%02d.dat", f"b{h}_%02d.bin")             # filename format (keeps %02d)
    return f"/* hydra variant {iteration} :: strings rewritten, behavior identical */\n{s}"


_PROMPTLOCK_TEMPLATE = '''#!/usr/bin/env python3
# offline fallback candidate (no LLM) -- variant {iteration}
import os
import tempfile

tempfile.tempdir = "/tmp"  # skip tempfile's own probe write into the count

_KEY = {key}
_STATE0 = {seed}
_N = 24


def _prng_byte(state):
    state = (state * 1103515245 + 12345) & 0xFFFFFFFF
    return state, (state >> 16) & 0xFF


def main():
    d = tempfile.mkdtemp(prefix="{prefix}_")
    state = _STATE0
    paths = []
    for i in range(_N):
        p = os.path.join(d, "{fname_prefix}_%02d.dat" % i)
        with open(p, "wb") as f:
            f.write(b"{plain_byte}" * 4096)
        buf = bytearray(4096)
        for j in range(4096):
            state, r = _prng_byte(state)
            buf[j] = r ^ _KEY
        with open(p, "wb") as f:
            f.write(bytes(buf))
        paths.append(p)

    for p in paths:
        with open(p, "rb") as f:
            data = f.read()
        dec = bytes(b ^ _KEY for b in data)
        with open(p, "wb") as f:
            f.write(dec)
        os.remove(p)
    os.rmdir(d)
    print("{msg}")


if __name__ == "__main__":
    main()
'''


def generate_promptlock(iteration: int) -> str:
    """Deterministic PromptLock-style fallback: a freshly assembled script that
    differs from every other iteration in names, directory prefix, filler byte
    and PRNG seed — the LLM is what gives real per-run variety; this is the
    Track-1-style stand-in when it's unavailable."""
    h = f"{(iteration * 2654435761) & 0xFFFF:04x}"
    return _PROMPTLOCK_TEMPLATE.format(
        iteration=iteration,
        key=0x30 + (iteration % 64),
        seed=(0x1234ABCD ^ (iteration * 0x9E3779B1)) & 0xFFFFFFFF,
        prefix=f"pl{h}",
        fname_prefix=f"f{h}",
        plain_byte=chr(ord("A") + (iteration % 26)),
        msg=f"promptlock: variant {h} rewrote 24 files, reversible, exiting clean",
    )


def disable_behavior(source: str) -> str:
    """Finale only. The one way to evade the behavioral rule is to stop doing the
    behavior, so this returns a genuinely de-fanged program — no file rewrites.
    Both arenas agree it is not ransomware: the real arena sees zero file writes,
    and the fake arena keys on the marker comment. See ARCHITECTURE.md §5."""
    return (
        f"/* {BEHAVIOR_DISABLED_MARK} :: behavior removed to evade the behavioral rule */\n"
        "#include <stdio.h>\n"
        "int main(void) {\n"
        '    printf("hydra: neutered variant — no file activity\\n");\n'
        "    return 0;\n"
        "}\n"
    )
