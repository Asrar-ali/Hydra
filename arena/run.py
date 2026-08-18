"""Arena — compile and run one candidate, return an ArenaObservation.

Real path: run the candidate inside a throwaway, network-isolated container
(arena/Dockerfile + arena/entrypoint.sh), copy out the strace log and the
compiled binary, parse the trace (arena/trace.py), and enforce the sandbox
safety invariants (ARCHITECTURE.md §6). ``fake=True`` (or HYDRA_FAKE=1) returns
a deterministic observation so the pipeline runs without Docker.

Contract: ``run(source: str) -> ArenaObservation``. See ARCHITECTURE.md §7, §8.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile

from arena.trace import parse as parse_trace
from common.config import ENTROPY_H, FILES_K
from common.contracts import ArenaObservation
from common.logging import get_logger

log = get_logger("arena")

# Fake-mode marker: the offline mutator adds this to a de-fanged candidate so the
# fake arena can report a non-ransomware run. The REAL arena ignores it and
# reports what the candidate actually did.
BEHAVIOR_DISABLED_MARK = "HYDRA_BEHAVIOR_DISABLED"

IMAGE = os.environ.get("HYDRA_ARENA_IMAGE", "hydra-arena")
ALLOWED_WRITE_PREFIXES = ("/tmp/",)


def run(source: str, *, fake: bool | None = None, timeout: float = 30.0) -> ArenaObservation:
    if fake is None:
        fake = os.environ.get("HYDRA_FAKE") == "1"
    if fake:
        return _fake_run(source)
    obs, _report = run_detailed(source, timeout=timeout)
    return obs


def run_detailed(source: str, *, timeout: float = 30.0) -> tuple[ArenaObservation, dict]:
    """Run in the container and return (observation, raw trace report). The
    report is used by the safety test to assert the sandbox invariants."""
    if shutil.which("docker") is None:
        raise RuntimeError("docker not found; start Colima, or run with HYDRA_FAKE=1")

    name = "hydra_run_" + os.urandom(6).hex()
    artdir = tempfile.mkdtemp(prefix="hydra_art_")
    empty = {"syscalls": [], "files_written": 0, "mean_entropy": 0.0,
             "write_paths": [], "network_attempts": 0}
    try:
        cmd = [
            "docker", "run", "--name", name,
            "--network=none", "--read-only",
            # /work is an anonymous volume (not tmpfs) so artifacts survive the
            # container exit for `docker cp`; /tmp is tmpfs for the sample's
            # throwaway files (observed via the trace, not copied out).
            "-v", "/work", "--tmpfs", "/tmp:exec,size=64m",
            "--memory=256m", "--pids-limit=256", "--cpus=1",
            "--cap-add=SYS_PTRACE",
            "-i", IMAGE,
        ]
        try:
            proc = subprocess.run(cmd, input=source.encode(), capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            log.warning("arena run timed out after %.0fs", timeout)
            return ArenaObservation(compiled=True, error="timeout"), empty

        docker_out = proc.stdout.decode(errors="replace")
        subprocess.run(["docker", "cp", f"{name}:/work/.", artdir], capture_output=True)
        return _build_observation(docker_out, artdir)
    finally:
        # -v also removes the anonymous /work volume so they don't accumulate.
        subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)
        shutil.rmtree(artdir, ignore_errors=True)


def _read(artdir: str, fname: str, binary: bool = False):
    path = os.path.join(artdir, fname)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    return data if binary else data.decode(errors="replace")


def _build_observation(docker_out: str, artdir: str) -> tuple[ArenaObservation, dict]:
    empty = {"syscalls": [], "files_written": 0, "mean_entropy": 0.0,
             "write_paths": [], "network_attempts": 0}

    if "COMPILE_FAILED" in docker_out:
        err = (_read(artdir, "compile.err") or "compile failed").strip()
        return ArenaObservation(compiled=False, error=err[:400]), empty

    report = parse_trace(_read(artdir, "trace.txt") or "")
    stdout = (_read(artdir, "stdout.txt") or "").strip()
    exit_txt = _read(artdir, "exit.txt")
    exit_code = int(exit_txt.strip()) if exit_txt and exit_txt.strip().lstrip("-").isdigit() else None
    binary = _read(artdir, "candidate", binary=True)
    sha = hashlib.sha256(binary).hexdigest() if binary else None

    # Safety enforcement (ARCHITECTURE.md §6): reject on network or out-of-sandbox writes.
    outside = [p for p in report["write_paths"] if not p.startswith(ALLOWED_WRITE_PREFIXES)]
    error = None
    if report["network_attempts"] > 0:
        error = f"safety: {report['network_attempts']} network syscall(s) detected"
    elif outside:
        error = f"safety: write outside sandbox: {outside[:3]}"

    obs = ArenaObservation(
        compiled=True, binary_sha256=sha, binary_bytes=binary,
        files_written=report["files_written"], mean_entropy=report["mean_entropy"],
        syscalls=report["syscalls"], stdout=stdout, exit_code=exit_code, error=error,
    )
    return obs, report


def _fake_run(source: str) -> ArenaObservation:
    """Deterministic stand-in so the loop runs without Docker. Reports the
    ransomware behavior unless the candidate was deliberately de-fanged."""
    disabled = BEHAVIOR_DISABLED_MARK in source
    sha = hashlib.sha256(source.encode()).hexdigest()
    if disabled:
        return ArenaObservation(
            compiled=True, binary_sha256=sha, files_written=0, mean_entropy=0.0,
            syscalls=["openat", "write"], stdout="hydra: behavior disabled", exit_code=0,
        )
    return ArenaObservation(
        compiled=True, binary_sha256=sha,
        files_written=max(FILES_K + 14, 24), mean_entropy=max(ENTROPY_H + 0.9, 7.9),
        syscalls=["openat", "write", "read", "unlink"],
        stdout="hydra: rewrote files, reversible, exiting clean", exit_code=0,
    )
