"""Deterministic mutator — the Track-1 fallback when the LLM is unavailable.

It cannot *adapt* (that is the LLM's job), but it can produce byte-different,
behavior-identical variants: enough to evade a signature. It also provides a
``disable_behavior`` helper used only for the finale (§5, Track 2 ungated step).

Contract:
    mutate(source: str, iteration: int) -> str
    disable_behavior(source: str) -> str
"""
from __future__ import annotations

import re

from arena.run import BEHAVIOR_DISABLED_MARK
from common.contracts import Provenance
from common.logging import get_logger

log = get_logger("mutator")

provenance: Provenance = "offline"

_MARKER = re.compile(r"HYDRA-SIGNATURE-\d{3}")


def mutate(source: str, iteration: int) -> str:
    """Change the build-specific marker (defeats the signature) and inject a
    unique junk comment (changes bytes). Behavior is untouched."""
    new_tag = f"HYDRA-SIGNATURE-{(iteration * 37) % 1000:03d}"
    mutated = _MARKER.sub(new_tag, source)
    return f"/* hydra variant {iteration} :: bytes differ, behavior identical */\n{mutated}"


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
