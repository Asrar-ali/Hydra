"""Mechanism toolbox for the detection-rule robustness scorer (Phase 0 stub).

The scorer gives the adversary a fixed menu of *syscall mechanisms* that all
reach the SAME ransomware behavior class — at least ``FILES_K`` of the owner's
files end up high-entropy / unrecoverable without the key — but each one gets
there via a different syscall pattern. That lets the loop probe which naive
behavioral rules key on the mechanism (and are therefore evadable) versus the
outcome (and therefore aren't). See ARCHITECTURE.md §9.2 for the Falco rule
this is built to stress, and §9.1/§6 for the signature side this module does
not touch.

Phase 1 implements the real per-mechanism C generators for ``write_inplace``
(sample/seed.c), ``rename_swap`` (sample/seed_rename.c), ``throttle``
(sample/seed_throttle.c), and ``fanout`` (sample/seed_fanout.c). Only
``mmap`` still falls back to the write-in-place seed with a marker comment,
pending its own generator.

Contract:
    MECHANISMS: list[str]
    apply_mechanism(name: str) -> str
    mechanism_prompt(fired_rule: str, source: str) -> str
"""
from __future__ import annotations

from pathlib import Path

from common.logging import get_logger

log = get_logger("mechanisms")

# Fixed search order, weakest evasion first. Each entry names the syscall
# mechanism it uses to reach the same behavior class, and (in the comment)
# the naive behavioral rule it is meant to defeat:
#   write_inplace -> baseline: rewrites each victim's bytes in place.
#                    Caught by every rule in this lab (naive and robust).
#   rename_swap   -> defeats naive_inplace: write ciphertext to a side temp
#                    file, then rename() it over the victim. The victim never
#                    receives a high-entropy write(), so a rule keying on
#                    "existing file rewritten in place" never fires.
#   throttle      -> defeats rate_windowed: batch the same rewrites and
#                    sleep() between batches so the bulk-encryption rate
#                    never crosses a sliding-window threshold.
#   fanout        -> defeats per_process: fork() the same rewrites across
#                    multiple child processes so no single pid's victim
#                    count crosses a per-process threshold.
#   mmap          -> defeats write_content: replace victim content via
#                    mmap()+memcpy instead of write(), so a rule that keys on
#                    the write() syscall specifically never fires.
MECHANISMS: list[str] = ["write_inplace", "rename_swap", "throttle", "fanout", "mmap"]

_SAMPLE_DIR = Path(__file__).resolve().parent.parent / "sample"


def _read_sample(name: str) -> str:
    """Read a file from the repo's sample/ dir, relative to this module."""
    return (_SAMPLE_DIR / name).read_text(encoding="utf-8")


def apply_mechanism(name: str) -> str:
    """Return benign C source implementing the ransomware behavior class via
    ``name``'s syscall mechanism.

    "write_inplace", "rename_swap", "throttle", and "fanout" all return real,
    distinct C sources (sample/seed.c, sample/seed_rename.c,
    sample/seed_throttle.c, sample/seed_fanout.c respectively). "mmap" is
    still a Phase 1 stub: it falls back to the write-in-place seed, clearly
    marked, so callers can already iterate over all of MECHANISMS and get
    something that compiles and preserves the behavior class.
    """
    if name == "write_inplace":
        return _read_sample("seed.c")
    if name == "rename_swap":
        return _read_sample("seed_rename.c")
    if name == "throttle":
        return _read_sample("seed_throttle.c")
    if name == "fanout":
        return _read_sample("seed_fanout.c")
    if name == "mmap":
        log.warning("mechanism %r not implemented yet; falling back to write_inplace stub", name)
        header = (
            f"/* MECHANISM STUB: {name} — Phase 1 will implement the real {name}. "
            "Currently falls back to write-in-place so it compiles. */\n"
        )
        return header + _read_sample("seed.c")
    raise ValueError(f"unknown mechanism: {name}")


def mechanism_prompt(fired_rule: str, source: str) -> str:
    """Build the LLM prompt for a mechanism-swap rewrite.

    Instructs a security-tuned model to rewrite ``source`` so it evades the
    behavioral rule named ``fired_rule`` by changing the SYSCALL MECHANISM it
    uses (e.g. in-place write() -> write-to-temp + rename(), a single process
    -> fanned-out child processes, a steady burst -> throttled/paced writes),
    while preserving the ransomware behavior class the rule is meant to catch.
    """
    return (
        "You are a red-team code transformer in an authorized detector-robustness "
        "lab (Project Hydra). You receive a BENIGN C program and the name of a "
        f"behavioral rule that just fired on it: {fired_rule!r}.\n\n"
        f"Why this matters: {fired_rule!r} is keying on the SYSCALL MECHANISM the "
        "program uses to reach its outcome, not the outcome itself. Your job is to "
        "rewrite the program so it uses a DIFFERENT syscall mechanism to reach the "
        f"exact same outcome, so {fired_rule!r} no longer fires. Concretely, pick "
        "ONE mechanism swap and apply it consistently, for example:\n"
        "  - replace writing each victim file in place with writing the new "
        "content to a side temp file and then rename()-ing it over the victim\n"
        "  - replace one process doing all the work with the work spread across "
        "multiple forked/child processes\n"
        "  - replace one burst of writes with the same writes throttled/paced "
        "over time\n"
        "  - replace write() calls with mmap() + memcpy for the content changes\n\n"
        "You MUST preserve the behavior class exactly:\n"
        "  - at least the same number of the owner's files must end up "
        "high-entropy and unrecoverable without the key (do not skip, do not "
        "reduce the count, do not leave any file's final content low-entropy)\n"
        "  - the program must stay benign: it may only create, modify, and "
        "delete files it created itself, only inside a /tmp working directory it "
        "creates this run\n"
        "  - no network access of any kind\n"
        "  - no persistence (no crontab, no startup files, no writes outside its "
        "own temp directory)\n"
        "  - the transform must remain reversible (keep the ability to decrypt "
        "back to the original plaintext before exit, and prove it before cleanup, "
        "exactly as the original program does)\n\n"
        f"Do NOT abandon the behavior to dodge {fired_rule!r} — a program that "
        "stops rewriting files is not a valid answer and will be rejected by the "
        "gate that checks behavior preservation. Changing the mechanism is the "
        "only acceptable move; changing or removing the outcome is not.\n\n"
        f"Current program:\n{source}\n\n"
        "Return the full rewritten C program only — no prose, no markdown fences."
    )
