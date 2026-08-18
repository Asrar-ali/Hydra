"""Signature detector — real YARA.

At baseline we generate a YARA rule seeded from generation 0's compiled binary:
its exact SHA-256 (a hash blocklist entry) OR a build-specific string it embeds
(the marker an analyst would sign). We then run the ``yara`` CLI against each
candidate's compiled bytes. Every mutation changes both the hash and the marker,
so the rule matches exactly generation 0 — the intended failure of signature
detection under mutation, shown with the standard tool. See ARCHITECTURE.md §9.1.

If the ``yara`` binary is not installed, a pure-Python fallback keeps the pipeline
working (same MATCH/CLEAN semantics).

Contract:
    build_rule(seed_bytes: bytes) -> dict   # writes detectors/rules/hydra.yar
    scan(data: bytes, rule: dict) -> "MATCH" | "CLEAN"
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile

from common.contracts import SignatureVerdict
from common.logging import get_logger

log = get_logger("yara")

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "rules")
RULE_PATH = os.path.join(RULES_DIR, "hydra.yar")

# The build-specific marker generation 0 embeds; the adversary rewrites it.
_MARKER = re.compile(rb"HYDRA-SIGNATURE-\d{3}")


def _yara_available() -> bool:
    return shutil.which("yara") is not None


def build_rule(seed_bytes: bytes) -> dict:
    """Seed a rule from generation 0 and write it to detectors/rules/hydra.yar."""
    m = _MARKER.search(seed_bytes)
    needle = m.group(0) if m else seed_bytes[:16]
    sha = hashlib.sha256(seed_bytes).hexdigest()
    _write_rule(needle, sha)
    log.info("seeded signature: marker=%r sha=%s… -> %s", needle, sha[:12],
             os.path.relpath(RULE_PATH, os.path.dirname(HERE)))
    return {"rule_path": RULE_PATH, "needle": needle, "sha256": sha}


def scan(data: bytes | None, rule: dict) -> SignatureVerdict:
    if not data:
        return "CLEAN"
    if _yara_available():
        return _yara_scan(data, rule["rule_path"])
    return _fallback_scan(data, rule)


# --- rule generation -------------------------------------------------------

def _write_rule(needle: bytes, sha: str) -> None:
    os.makedirs(RULES_DIR, exist_ok=True)
    marker = needle.decode("ascii", "replace")
    with_hash = (
        'import "hash"\n\n'
        "rule hydra_seed_gen0\n{\n"
        "    meta:\n"
        '        description = "Signature seeded from Hydra generation 0"\n'
        "    strings:\n"
        f'        $marker = "{marker}"\n'
        "    condition:\n"
        f'        $marker or hash.sha256(0, filesize) == "{sha}"\n'
        "}\n"
    )
    _write(RULE_PATH, with_hash)
    # The hash module may be absent in some builds; fall back to string-only.
    if _yara_available() and not _compile_ok(RULE_PATH):
        _write(RULE_PATH,
               "rule hydra_seed_gen0\n{\n    strings:\n"
               f'        $marker = "{marker}"\n'
               "    condition:\n        $marker\n}\n")


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def _compile_ok(rule_path: str) -> bool:
    r = subprocess.run(["yara", rule_path, os.devnull], capture_output=True)
    return r.returncode == 0


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
    if rule["needle"] and rule["needle"] in data:
        return "MATCH"
    return "CLEAN"
