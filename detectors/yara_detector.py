"""Signature detector.

Lane 2 owns this. The real implementation writes a YARA rule seeded from
generation 0 and runs the ``yara`` binary against each candidate's compiled
bytes. Until yara is wired, a pure-Python fallback scans for the seed's
build-specific marker so the pipeline is runnable and Track 1 (signature
evasion) still demonstrates. See ARCHITECTURE.md §9.1.

Contract:
    build_rule(seed_bytes: bytes) -> dict
    scan(data: bytes, rule: dict) -> "MATCH" | "CLEAN"
"""
from __future__ import annotations

import hashlib
import re

from common.contracts import SignatureVerdict
from common.logging import get_logger

log = get_logger("yara")

# The build-specific marker in sample/seed.c that a signature keys on. The
# adversary rewrites this to evade — exactly the point of §9.1.
_MARKER = re.compile(rb"HYDRA-SIGNATURE-\d{3}")


def build_rule(seed_bytes: bytes) -> dict:
    """Seed a rule from generation 0: its sha256 plus a build-specific needle."""
    m = _MARKER.search(seed_bytes)
    needle = m.group(0) if m else seed_bytes[:16]
    log.info("seeded signature: needle=%r", needle)
    return {"sha256": hashlib.sha256(seed_bytes).hexdigest(), "needle": needle}


def scan(data: bytes, rule: dict) -> SignatureVerdict:
    """MATCH if the exact seed hash or its build-specific needle is present."""
    if hashlib.sha256(data).hexdigest() == rule["sha256"]:
        return "MATCH"
    if rule["needle"] and rule["needle"] in data:
        return "MATCH"
    return "CLEAN"

    # TODO(lane2): replace the above with real YARA — write rule to
    # detectors/rules/hydra.yar, `yara hydra.yar <binary>`, MATCH on nonzero hits.
