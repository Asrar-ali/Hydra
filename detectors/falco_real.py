"""Real Falco (eBPF) behavioral sensor — opt-in via ``HYDRA_REAL_FALCO=1``.

Spike-validated against this project's Colima VM (kernel 6.8, BTF present):
the modern eBPF driver loads with no kernel module or headers, and a rule can
capture full write-buffer content (``-S 4096 -b``, matching strace's ``-xx -s
4096``) — real entropy, not just event counts.

What didn't work: Falco's docker/CRI container-name enrichment. It never
resolved in this setup — every ``container.name`` came back null, for every
container, old and new, regardless of which socket path was mounted where.
So this module does NOT scope events by container identity. Instead it scopes
by PROCESS TREE: ``arena.run`` hands us the run's root pid (from ``docker
inspect``), and we keep only sensor events whose pid, ppid, or one of
Falco's own ancestor-pid fields (``proc.apid[1..4]``) equals it — validated
to correctly thread back through a 3-level-deep process tree in the spike,
comfortably covering our real depth (entrypoint -> strace -> candidate).

One long-lived, privileged, host-pid-namespace sensor container for the whole
process — eBPF probe attach takes a second or two, too slow to pay per run.
It free-runs, JSON-logging every write() under /tmp and every connect() on
the host; ``observe()`` tails its logs for a run's time window and filters by
the process-tree check above. See ARCHITECTURE.md §8, §9.2.

Contract:
    available() -> bool                          # starts the sensor lazily, caches the result
    observe(root_pid, since, timeout) -> dict     # same shape as arena/trace.py::parse
    stop() -> None                                # tears the sensor down (idempotent)
"""
from __future__ import annotations

import atexit
import base64
import json
import os
import shutil
import subprocess
import time

from common.config import ENTROPY_H
from common.entropy import shannon_entropy
from common.logging import get_logger

log = get_logger("falco_real")

IMAGE = os.environ.get("HYDRA_FALCO_IMAGE", "hydra-falco")
CONTAINER = "hydra-falco-sensor"
_ANCESTOR_DEPTH = 4  # proc.apid[1..this] — validated against a 3-deep tree with headroom

_started = False
_ready = False


def available() -> bool:
    """Start the sensor on first call (idempotent within the process), return
    whether it's actually up with a probe attached."""
    global _started, _ready
    if not _started:
        _started = True
        _ready = _start()
    return _ready


def _start() -> bool:
    if shutil.which("docker") is None:
        return False
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)  # clear a stale run
    cmd = [
        "docker", "run", "-d", "--name", CONTAINER,
        "--privileged", "--pid=host",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "/run/containerd/containerd.sock:/run/containerd/containerd.sock",
        "-v", "/dev:/host/dev", "-v", "/proc:/host/proc:ro", "-v", "/boot:/host/boot:ro",
        "-v", "/lib/modules:/host/lib/modules:ro", "-v", "/usr:/host/usr:ro", "-v", "/etc:/host/etc:ro",
        IMAGE,
        "falco", "-A", "-o", "engine.kind=modern_ebpf", "-o", "json_output=true",
        "-r", "/etc/hydra_rules.yaml", "-S", "4096", "-b",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        log.warning("could not start the real-falco sensor: %s", r.stderr.strip()[:300])
        return False
    for _ in range(50):  # up to ~10s for the eBPF probe to attach
        out = subprocess.run(["docker", "logs", CONTAINER], capture_output=True, text=True)
        if "modern BPF probe" in out.stdout + out.stderr:
            log.info("real falco sensor up (modern eBPF, image=%s)", IMAGE)
            atexit.register(stop)
            return True
        if out.returncode != 0:
            break
        time.sleep(0.2)
    log.warning("real-falco sensor did not report a ready probe in time")
    stop()
    return False


def stop() -> None:
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)


def _belongs_to(fields: dict, root_pid: int) -> bool:
    if fields.get("proc.pid") == root_pid or fields.get("proc.ppid") == root_pid:
        return True
    return any(fields.get(f"proc.apid[{i}]") == root_pid for i in range(1, _ANCESTOR_DEPTH + 1))


def _decode_buffer(b64: str) -> bytes | None:
    # Falco's -b flag base64-encodes the raw buffer; the JSON writer then
    # encodes that string again — empirically two layers, not one.
    try:
        return base64.b64decode(base64.b64decode(b64))
    except Exception:  # noqa: BLE001 - truncated/malformed capture, skip it
        return None


def observe(root_pid: int, since: float, timeout: float = 30.0) -> dict:
    """Correlate this run's syscalls from the sensor's log by process tree.
    Returns the same shape as ``arena.trace.parse``."""
    empty = {"syscalls": [], "files_written": 0, "encrypted_files": 0,
             "mean_entropy": 0.0, "write_paths": [], "network_attempts": 0}
    since_arg = f"{max(since - 1, 0):.0f}"
    try:
        r = subprocess.run(["docker", "logs", "--since", since_arg, CONTAINER],
                           capture_output=True, text=True, timeout=timeout + 5)
    except subprocess.TimeoutExpired:
        log.warning("timed out reading the real-falco sensor's log")
        return empty

    last_entropy: dict[str, float] = {}
    written: set[str] = set()
    network = 0
    for line in (r.stdout + r.stderr).splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        fields = obj.get("output_fields", {})
        if not _belongs_to(fields, root_pid):
            continue

        rule = obj.get("rule", "")
        if rule == "Hydra Sensor Connect":
            network += 1
        elif rule == "Hydra Sensor Write":
            path = fields.get("fd.name")
            data = _decode_buffer(fields.get("evt.buffer", ""))
            if not path or data is None:
                continue
            last_entropy[path] = shannon_entropy(data)
            written.add(path)

    paths = sorted(written)
    mean = sum(last_entropy[p] for p in paths) / len(paths) if paths else 0.0
    encrypted = sum(1 for p in paths if last_entropy[p] >= ENTROPY_H)
    syscalls = (["write"] if written else []) + (["connect"] if network else [])
    return {
        "syscalls": syscalls,
        "files_written": len(paths),
        "encrypted_files": encrypted,
        "mean_entropy": mean,
        "write_paths": paths,
        "network_attempts": network,
    }
