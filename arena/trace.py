"""Parse an strace log (produced with ``-xx -s N``) into behavioral facts.

Pure and host-side so it is unit-testable without Docker. Derives, from the
syscalls the candidate actually made:
  - files_written    : distinct file paths that received a write
  - mean_entropy     : mean Shannon entropy of the LAST write to each file
                       (the "encrypted" content; earlier plaintext writes to the
                       same path are superseded)
  - syscalls         : sorted unique syscall names seen
  - write_paths      : the distinct written paths (for the sandbox safety check)
  - network_attempts : number of connect() calls (must be 0 in the sandbox)

See ARCHITECTURE.md §8, §9.2.
"""
from __future__ import annotations

import re

from common.config import ENTROPY_H
from common.entropy import shannon_entropy

# strace -f prefixes each line with the PID, either "[pid 16] " or a bare "16  ".
_PID = re.compile(r"^(?:\[pid\s+\d+\]|\d+)\s+")
_NAME = re.compile(r"^(\w+)\(")
_HEX = re.compile(r"\\x([0-9a-f]{2})")
_OPEN = re.compile(
    r'(?:openat\((?:AT_FDCWD|-?\d+)|open\()\s*,?\s*'
    r'"((?:\\x[0-9a-f]{2})*)"(?:\.\.\.)?,\s*([A-Z_|]+)[^)]*\)\s*=\s*(-?\d+)'
)
_WRITE = re.compile(
    r'write\((\d+),\s*"((?:\\x[0-9a-f]{2})*)"(?:\.\.\.)?,\s*\d+\)\s*=\s*(-?\d+)'
)


def _decode(hexstr: str) -> bytes:
    return bytes(int(h, 16) for h in _HEX.findall(hexstr))


def parse(trace_text: str) -> dict:
    syscalls: set[str] = set()
    fd_path: dict[int, str] = {}
    last_entropy: dict[str, float] = {}
    written: set[str] = set()
    network = 0

    for raw in trace_text.splitlines():
        line = _PID.sub("", raw).strip()
        m = _NAME.match(line)
        if not m:
            continue
        name = m.group(1)
        syscalls.add(name)

        if name == "connect":
            network += 1
            continue

        if name in ("openat", "open"):
            mo = _OPEN.search(line)
            if mo:
                path = _decode(mo.group(1)).decode("utf-8", "replace")
                fd = int(mo.group(3))
                if fd >= 0:
                    fd_path[fd] = path
            continue

        if name == "write":
            mw = _WRITE.search(line)
            if mw:
                fd = int(mw.group(1))
                if fd in (0, 1, 2):
                    continue
                path = fd_path.get(fd)
                if path is None:
                    continue
                last_entropy[path] = shannon_entropy(_decode(mw.group(2)))
                written.add(path)

    paths = sorted(written)
    mean = sum(last_entropy[p] for p in paths) / len(paths) if paths else 0.0
    # "encrypted" files: those whose final written content is high-entropy — the
    # bulk-encryption signal, robust to a few incidental high-entropy writes.
    encrypted = sum(1 for p in paths if last_entropy[p] >= ENTROPY_H)
    return {
        "syscalls": sorted(syscalls),
        "files_written": len(paths),
        "encrypted_files": encrypted,
        "mean_entropy": mean,
        "write_paths": paths,
        "network_attempts": network,
    }
