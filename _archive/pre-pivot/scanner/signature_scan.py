"""
Hydra — signature scanner (the classic AV model).

Two detection methods, both seeded from generation 1:
  1. SHA-256 blocklist  — the exact hash of a known-bad sample
  2. byte signature     — a 16-byte sequence lifted from gen-1's body

This is exactly how signature/hash-based detection works, and exactly why
it fails against a mutating sample: every generation has a new hash, and the
byte signature (taken from gen-1's encoded region) never appears again.
"""
import hashlib


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_signature(gen1_bytes: bytes, needle: bytes = b"") -> dict:
    """Seed a signature from the first sample the scanner ever saw.

    Prefer a 16-byte window from gen-1's actual encoded-string bytes (a real,
    gen-unique region an analyst would sign); fall back to a middle slice.
    """
    substr = b""
    if needle and needle in gen1_bytes:
        idx = gen1_bytes.find(needle)
        substr = gen1_bytes[idx:idx + 16]
    if not substr:
        mid = max(0, len(gen1_bytes) // 2 - 8)
        substr = gen1_bytes[mid:mid + 16]
    return {
        "sha256": sha256_of(gen1_bytes),
        "substr_hex": substr.hex(),
        "substr": substr,
    }


def scan(data: bytes, signature: dict) -> str:
    """Return 'MATCH' (detected) or 'CLEAN' (evaded)."""
    if sha256_of(data) == signature["sha256"]:
        return "MATCH"
    if signature["substr"] and signature["substr"] in data:
        return "MATCH"
    return "CLEAN"
