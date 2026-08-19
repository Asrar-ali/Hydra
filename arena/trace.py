"""Parse an strace log (produced with ``-xx -s N``) into behavioral facts.

Pure and host-side so it is unit-testable without Docker. Derives, from the
syscalls the candidate actually made:
  - files_written        : distinct file paths that received a write
  - mean_entropy         : mean Shannon entropy of the LAST write to each file
                           (the "encrypted" content; earlier plaintext writes to
                           the same path are superseded)
  - encrypted_files      : distinct written paths whose final write is high-entropy
                           (legacy write()-based count; still counts scratch temps)
  - encrypted_in_place   : existing files OVERWRITTEN in place with high-entropy
                           content (a file that received a prior write, then a
                           high-entropy one). What a naive canary rule keys on —
                           and what a rename() swap evades.
  - encrypted_outcome    : distinct VICTIM paths that END high-entropy by ANY
                           mechanism — follows rename() to the real destination
                           and excludes scratch temps that were renamed away. The
                           behavior class: "the owner's files ended unrecoverable".
  - syscalls             : sorted unique syscall names seen
  - write_paths          : the distinct written paths (for the sandbox safety check)
  - network_attempts     : number of connect() calls (must be 0 in the sandbox)

The split between ``encrypted_in_place`` (mechanism-specific) and
``encrypted_outcome`` (mechanism-independent) is what lets the behavioral rule
and the behavior-preservation gate diverge: an adversary can drive the first to
zero (evade a naive rule) while the second stays high (behavior preserved). See
ARCHITECTURE.md §8, §9.2.
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
# rename / renameat / renameat2 — grab every quoted (hex) path on the line; the
# dirfd args are AT_FDCWD (unquoted), so src is the first path and dst the last.
_QPATH = re.compile(r'"((?:\\x[0-9a-f]{2})*)"')


def _decode(hexstr: str) -> bytes:
    return bytes(int(h, 16) for h in _HEX.findall(hexstr))


def parse(trace_text: str) -> dict:
    syscalls: set[str] = set()
    fd_path: dict[int, str] = {}
    last_entropy: dict[str, float] = {}   # final direct-write entropy per path
    write_count: dict[str, int] = {}      # how many direct writes each path received
    renames: list[tuple[str, str]] = []   # (src, dst) in order
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

        if name.startswith("rename"):
            # rename("src","dst"), renameat(AT_FDCWD,"src",AT_FDCWD,"dst"), renameat2(...)
            m_end = line.find("=")
            paths = _QPATH.findall(line if m_end < 0 else line[:m_end])
            if len(paths) >= 2:
                src = _decode(paths[0]).decode("utf-8", "replace")
                dst = _decode(paths[-1]).decode("utf-8", "replace")
                renames.append((src, dst))
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
                write_count[path] = write_count.get(path, 0) + 1
                written.add(path)

    paths = sorted(written)
    mean = sum(last_entropy[p] for p in paths) / len(paths) if paths else 0.0
    # "encrypted" files (legacy): distinct written paths whose final content is
    # high-entropy. Kept unchanged for existing callers; still counts scratch
    # temps as if they were victims — which is exactly the imprecision the two
    # facts below resolve.
    encrypted = sum(1 for p in paths if last_entropy[p] >= ENTROPY_H)

    # Mechanism-independent view of the same event stream.
    rename_srcs = {src for src, _ in renames}
    # Follow each rename: the source's final content now lives at the destination.
    final_entropy: dict[str, float] = dict(last_entropy)
    for src, dst in renames:
        if src in last_entropy:
            final_entropy[dst] = last_entropy[src]

    # encrypted_in_place (naive rule): an EXISTING file overwritten in place with
    # high-entropy content — it received a prior write, then a high-entropy one.
    # A file replaced via write-to-temp + rename() never matches (the temp is
    # written once; the victim never gets a high-entropy write), so this is 0.
    encrypted_in_place = sum(
        1 for p, n in write_count.items()
        if p not in rename_srcs and n >= 2 and last_entropy.get(p, 0.0) >= ENTROPY_H
    )

    # encrypted_outcome (robust rule + gate): distinct VICTIM paths that END
    # high-entropy by any mechanism. Temps that were renamed away are not victims.
    victims = [p for p in final_entropy if p not in rename_srcs]
    encrypted_outcome = sum(1 for p in victims if final_entropy[p] >= ENTROPY_H)

    return {
        "syscalls": sorted(syscalls),
        "files_written": len(paths),
        "encrypted_files": encrypted,
        "encrypted_in_place": encrypted_in_place,
        "encrypted_outcome": encrypted_outcome,
        "mean_entropy": mean,
        "write_paths": paths,
        "network_attempts": network,
    }
