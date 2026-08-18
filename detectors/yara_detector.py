"""Signature detector — real YARA, multi-indicator family rule.

A real analyst does not sign a single label; they write a family rule keyed on
several characteristic artifacts and fire when enough of them are present. We
seed such a rule from generation 0's compiled binary — its exact SHA-256 plus the
characteristic strings it embeds (the marker, the temp-dir name, the status
message, the filename format) — and match when at least ``MIN_MATCH`` of the
strings appear. To evade, the adversary must rewrite MOST of those artifacts while
keeping behavior identical: a substantive change to the program's fingerprint,
not a one-line rename. See ARCHITECTURE.md §9.1.

If ``yara`` is not installed, a pure-Python fallback keeps the same semantics.

Contract:
    build_rule(seed_bytes: bytes) -> dict   # writes detectors/rules/hydra.yar
    scan(data: bytes, rule: dict) -> "MATCH" | "CLEAN"
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile

from common.contracts import SignatureVerdict
from common.logging import get_logger

log = get_logger("yara")

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "rules")
RULE_PATH = os.path.join(RULES_DIR, "hydra.yar")

# Characteristic strings generation 0 embeds — the family's fingerprint. The
# adversary must rewrite most of them (while preserving behavior) to evade.
SIGNATURE_STRINGS = [
    b"HYDRA-SIGNATURE-",           # the marker
    b"hydra_work",                 # temp working-dir name
    b"reversible, exiting clean",  # status message fragment
    b"file_%02d.dat",              # per-file name format
]
MIN_MATCH = 2  # fire when >= this many are present (a family rule)


def _yara_available() -> bool:
    return shutil.which("yara") is not None


def build_rule(seed_bytes: bytes) -> dict:
    """Seed a family rule from generation 0 and write detectors/rules/hydra.yar."""
    needles = [s for s in SIGNATURE_STRINGS if s in seed_bytes] or [seed_bytes[:16]]
    min_match = min(MIN_MATCH, len(needles))
    sha = hashlib.sha256(seed_bytes).hexdigest()
    _write_rule(needles, sha, min_match)
    log.info("seeded family signature: %d strings, fire on >=%d  -> %s",
             len(needles), min_match, os.path.relpath(RULE_PATH, os.path.dirname(HERE)))
    return {"rule_path": RULE_PATH, "needles": needles, "min_match": min_match, "sha256": sha}


def scan(data: bytes | None, rule: dict) -> SignatureVerdict:
    if not data:
        return "CLEAN"
    if _yara_available():
        return _yara_scan(data, rule["rule_path"])
    return _fallback_scan(data, rule)


# --- rule generation -------------------------------------------------------

def _yara_escape(b: bytes) -> str:
    return b.decode("ascii", "replace").replace("\\", "\\\\").replace('"', '\\"')


def _write_rule(needles: list[bytes], sha: str, min_match: int) -> None:
    os.makedirs(RULES_DIR, exist_ok=True)
    strings = "\n".join(f'        $s{i} = "{_yara_escape(n)}"' for i, n in enumerate(needles))
    cond = f"hash.sha256(0, filesize) == \"{sha}\" or {min_match} of them"
    rule = (
        'import "hash"\n\n'
        "rule hydra_seed_gen0\n{\n"
        '    meta:\n        description = "Family signature seeded from Hydra generation 0"\n'
        f"    strings:\n{strings}\n"
        f"    condition:\n        {cond}\n"
        "}\n"
    )
    _write(RULE_PATH, rule)
    if _yara_available() and not _compile_ok(RULE_PATH):
        # hash module unavailable in this build — drop it, keep the string family.
        rule_no_hash = (
            "rule hydra_seed_gen0\n{\n"
            f"    strings:\n{strings}\n"
            f"    condition:\n        {min_match} of them\n}}\n"
        )
        _write(RULE_PATH, rule_no_hash)


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _compile_ok(rule_path: str) -> bool:
    return subprocess.run(["yara", rule_path, os.devnull], capture_output=True).returncode == 0


# --- scanning --------------------------------------------------------------

def _yara_scan(data: bytes, rule_path: str) -> SignatureVerdict:
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        target = tf.name
    try:
        r = subprocess.run(["yara", rule_path, target], capture_output=True, text=True)
        return "MATCH" if r.stdout.strip() else "CLEAN"
    finally:
        os.unlink(target)


def _fallback_scan(data: bytes, rule: dict) -> SignatureVerdict:
    if hashlib.sha256(data).hexdigest() == rule["sha256"]:
        return "MATCH"
    hits = sum(1 for n in rule["needles"] if n in data)
    return "MATCH" if hits >= rule["min_match"] else "CLEAN"
