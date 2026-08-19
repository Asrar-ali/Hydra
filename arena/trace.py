"""Parse an strace log (produced with ``-f -tt -xx -s N``) into behavioral facts.

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
  - max_encrypted_per_pid: among the pids attributed at least one victim, the
                           most victims any single pid is attributed. A fan-out
                           mechanism (spread the work across child processes)
                           drives this below a per-process threshold while
                           encrypted_outcome stays high. 0 when there are no
                           victims.
  - max_rate_in_window   : the most distinct victims attributed within any
                           sliding time window of RATE_WINDOW_SECONDS. Needs
                           ``-tt`` timestamps in the trace; when they're absent
                           every event is attributed time 0.0, so this degrades
                           to encrypted_outcome (everything lands in one
                           window) rather than under-reporting. 0 when there
                           are no victims.
  - syscalls             : sorted unique syscall names seen
  - write_paths          : the distinct written paths (for the sandbox safety check)
  - network_attempts     : number of connect() calls (must be 0 in the sandbox)

The split between ``encrypted_in_place`` (mechanism-specific) and
``encrypted_outcome`` (mechanism-independent) is what lets the behavioral rule
and the behavior-preservation gate diverge: an adversary can drive the first to
zero (evade a naive rule) while the second stays high (behavior preserved).
``max_encrypted_per_pid`` and ``max_rate_in_window`` are two more
mechanism-independent facts about the same outcome set: each victim is
attributed to the pid + timestamp of the write that produced its final
high-entropy content (following rename() the same way ``encrypted_outcome``
does), so a fan-out-across-processes or a throttled-rate mechanism shows up
here even though the file-level outcome is unchanged. See ARCHITECTURE.md §8,
§9.2.
"""
from __future__ import annotations

import re

from common.config import ENTROPY_H, RATE_WINDOW_SECONDS
from common.entropy import shannon_entropy

# strace -f prefixes each line with the PID, either "[pid N] " or a bare
# "N  ". With -tt, a "HH:MM:SS.ffffff " wall-clock timestamp follows. Both
# prefixes are optional and independent so a trace with neither (or only one)
# still parses exactly like before — see the pid/timestamp attribution logic
# below, which treats an absent pid/timestamp as "everything shares pid None,
# timestamp 0.0" rather than failing to parse.
_PID = re.compile(r"^(?:\[pid\s+(\d+)\]|(\d+))\s+")
_TS = re.compile(r"^(\d{2}):(\d{2}):(\d{2})\.(\d{6})\s+")
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


def _seconds(h: str, mi: str, s: str, us: str) -> float:
    return int(h) * 3600 + int(mi) * 60 + int(s) + int(us) / 1_000_000


def parse(trace_text: str) -> dict:
    syscalls: set[str] = set()
    # fd -> path, keyed by (pid, fd): forked children each have their own fd
    # table and reuse the same low fd numbers (3, 4, ...) concurrently, so a
    # global fd map would cross-attribute one child's write to another child's
    # path once strace -f interleaves their lines. Keying by pid keeps each
    # process's descriptors separate (the fan-out mechanism depends on this).
    fd_path: dict[tuple[int | None, int], str] = {}
    last_entropy: dict[str, float] = {}   # final direct-write entropy per path
    last_write_meta: dict[str, tuple[int | None, float]] = {}  # path -> (pid, ts) of its last write
    write_count: dict[str, int] = {}      # how many direct writes each path received
    renames: list[tuple[str, str]] = []   # (src, dst) in order
    written: set[str] = set()
    network = 0
    pending: dict[int | None, str] = {}   # pid -> prefix of a split (unfinished) syscall

    for raw in trace_text.splitlines():
        line = raw.strip()
        pid: int | None = None
        ts = 0.0

        mp = _PID.match(line)
        if mp:
            pid = int(mp.group(1) or mp.group(2))
            line = line[mp.end():]

        mt = _TS.match(line)
        if mt:
            ts = _seconds(*mt.groups())
            line = line[mt.end():]

        # Reassemble strace -f split syscalls: under concurrency strace emits
        # "name(args <unfinished ...>" then later "<... name resumed>) = ret"
        # for the same pid, interleaved with other pids' lines. Rejoin them so
        # the fd/write regexes see a whole syscall. Fan-out traces are full of
        # these; without this most child opens/writes are silently dropped.
        if line.endswith("<unfinished ...>"):
            pending[pid] = line[:line.rindex("<unfinished")].rstrip()
            continue
        if line.startswith("<..."):
            resumed = line.find("resumed>")
            if resumed == -1:
                continue
            line = pending.pop(pid, "") + line[resumed + len("resumed>"):]

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
                    fd_path[(pid, fd)] = path
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
                path = fd_path.get((pid, fd))
                if path is None:
                    continue
                last_entropy[path] = shannon_entropy(_decode(mw.group(2)))
                last_write_meta[path] = (pid, ts)
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
    # Follow each rename: the source's final content — and the write that
    # produced it — now lives at the destination.
    final_entropy: dict[str, float] = dict(last_entropy)
    final_meta: dict[str, tuple[int | None, float]] = dict(last_write_meta)
    for src, dst in renames:
        if src in last_entropy:
            final_entropy[dst] = last_entropy[src]
        if src in last_write_meta:
            final_meta[dst] = last_write_meta[src]

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

    # Attribute each victim to the pid + timestamp of the write that produced
    # its final high-entropy content — final_meta already follows rename() the
    # same way final_entropy does, so a renamed-in victim is attributed to the
    # last write to the temp that was renamed onto it.
    victim_events = [
        final_meta.get(p, (None, 0.0)) for p in victims if final_entropy[p] >= ENTROPY_H
    ]

    per_pid_counts: dict[int | None, int] = {}
    for vpid, _vts in victim_events:
        per_pid_counts[vpid] = per_pid_counts.get(vpid, 0) + 1
    max_encrypted_per_pid = max(per_pid_counts.values()) if per_pid_counts else 0

    # Sliding window of width RATE_WINDOW_SECONDS: for each attributed
    # timestamp t, count how many attributed timestamps fall in [t, t+W); the
    # max over all such windows is the peak rate. Timestamps are sorted so the
    # inner scan can stop at the first one that falls outside the window.
    times = sorted(vts for _vpid, vts in victim_events)
    max_rate_in_window = 0
    for i, t0 in enumerate(times):
        count = 0
        for t in times[i:]:
            if t < t0 + RATE_WINDOW_SECONDS:
                count += 1
            else:
                break
        if count > max_rate_in_window:
            max_rate_in_window = count

    return {
        "syscalls": sorted(syscalls),
        "files_written": len(paths),
        "encrypted_files": encrypted,
        "encrypted_in_place": encrypted_in_place,
        "encrypted_outcome": encrypted_outcome,
        "max_encrypted_per_pid": max_encrypted_per_pid,
        "max_rate_in_window": max_rate_in_window,
        "mean_entropy": mean,
        "write_paths": paths,
        "network_attempts": network,
    }
