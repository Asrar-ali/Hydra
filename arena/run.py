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
import time
from dataclasses import replace

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


def run(source: str, *, fake: bool | None = None, timeout: float = 30.0,
        mode: str = "metamorphic") -> ArenaObservation:
    if fake is None:
        fake = os.environ.get("HYDRA_FAKE") == "1"
    if fake:
        return _fake_run(source)
    obs, _report = run_detailed(source, timeout=timeout, mode=mode)
    return obs


def run_detailed(source: str, *, timeout: float = 30.0,
                  mode: str = "metamorphic") -> tuple[ArenaObservation, dict]:
    """Run in the container and return (observation, raw trace report). The
    report is used by the safety test to assert the sandbox invariants.

    ``mode``: "metamorphic" (default) compiles ``source`` as C and runs the
    binary. "promptlock" runs ``source`` directly as a Python script (no
    compile step) — the runtime-generated-payload mode, ARCHITECTURE.md §9.3.

    The behavioral facts (files/entropy/network) come from parsing an
    in-container strace trace by default. Set ``HYDRA_REAL_FALCO=1`` to source
    them from a real Falco (eBPF) sensor instead — see detectors/falco_real.py
    and ARCHITECTURE.md §8. Falls back to strace automatically if the sensor
    isn't available; this default path is unchanged either way.
    """
    if os.environ.get("HYDRA_REAL_FALCO") == "1":
        from detectors import falco_real
        if falco_real.available():
            return _run_detailed_real_falco(source, timeout=timeout, mode=mode)
        log.warning("HYDRA_REAL_FALCO=1 but the sensor isn't available; using strace")
    return _run_detailed_strace(source, timeout=timeout, mode=mode)


def _docker_cmd(name: str, mode: str, *, no_strace: bool = False) -> list[str]:
    cmd = [
        "docker", "run", "--name", name,
        "--network=none", "--read-only",
        # /work is an anonymous volume (not tmpfs) so artifacts survive the
        # container exit for `docker cp`; /tmp is tmpfs for the sample's
        # throwaway files (observed via the trace, not copied out).
        "-v", "/work", "--tmpfs", "/tmp:exec,size=64m",
        "--memory=256m", "--pids-limit=256", "--cpus=1",
        "--cap-add=SYS_PTRACE",
    ]
    if no_strace:
        # the real-Falco path: a ptrace-traced process doesn't show up in
        # Falco's eBPF probe, so the entrypoint skips strace entirely here.
        cmd += ["-e", "HYDRA_NO_STRACE=1"]
    if mode == "promptlock":
        cmd += ["--entrypoint", "/usr/local/bin/hydra-run-script"]
    cmd += ["-i", IMAGE]
    return cmd


def _run_detailed_strace(source: str, *, timeout: float = 30.0,
                         mode: str = "metamorphic") -> tuple[ArenaObservation, dict]:
    if shutil.which("docker") is None:
        raise RuntimeError("docker not found; start Colima, or run with HYDRA_FAKE=1")

    name = "hydra_run_" + os.urandom(6).hex()
    artdir = tempfile.mkdtemp(prefix="hydra_art_")
    empty = {"syscalls": [], "files_written": 0, "encrypted_files": 0,
             "mean_entropy": 0.0, "write_paths": [], "network_attempts": 0}
    try:
        cmd = _docker_cmd(name, mode)
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


def _run_detailed_real_falco(source: str, *, timeout: float = 30.0,
                             mode: str = "metamorphic") -> tuple[ArenaObservation, dict]:
    """Same sandboxed container as ``_run_detailed_strace``, but the
    behavioral facts come from the real Falco sensor (detectors/falco_real.py)
    instead of parsing the in-container strace trace. Needs the container to
    still be running when we ask Docker for its pid, so this uses Popen
    instead of the blocking subprocess.run the strace path uses."""
    from detectors import falco_real

    if shutil.which("docker") is None:
        raise RuntimeError("docker not found; start Colima, or run with HYDRA_FAKE=1")

    name = "hydra_run_" + os.urandom(6).hex()
    artdir = tempfile.mkdtemp(prefix="hydra_art_")
    empty = {"syscalls": [], "files_written": 0, "encrypted_files": 0,
             "mean_entropy": 0.0, "write_paths": [], "network_attempts": 0}
    proc = None
    try:
        cmd = _docker_cmd(name, mode, no_strace=True)
        since = time.time()
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        proc.stdin.write(source.encode())
        proc.stdin.close()

        root_pid = None
        # The sensor's own eBPF event volume measurably slows down new
        # container starts on a busy host (observed 3-4s, occasionally more,
        # vs. ~0.1s with no sensor running) — budget generously rather than
        # give up and silently fall back to strace on an ordinary-speed host.
        for _ in range(100):  # up to ~10s for the container to actually start
            r = subprocess.run(["docker", "inspect", "--format", "{{.State.Pid}}", name],
                               capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip().isdigit() and int(r.stdout.strip()) > 0:
                root_pid = int(r.stdout.strip())
                break
            time.sleep(0.1)

        try:
            stdout_bytes, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            log.warning("arena run timed out after %.0fs", timeout)
            return ArenaObservation(compiled=True, error="timeout"), empty

        docker_out = stdout_bytes.decode(errors="replace")
        subprocess.run(["docker", "cp", f"{name}:/work/.", artdir], capture_output=True)

        if root_pid is None:
            # No trace.txt to fall back to here: HYDRA_NO_STRACE=1 was already
            # set on this container (strace and Falco can't both watch the
            # same process — see entrypoint.sh), so without a root pid there
            # is no behavioral signal at all. Surface that honestly instead of
            # silently returning a report full of zeros, which would look
            # exactly like "the candidate did nothing."
            log.warning("never saw the container's pid (host contention?); no behavioral signal for this run")
            obs, _ = _build_observation(docker_out, artdir)
            return replace(obs, error="real-falco: could not correlate this run"), empty

        report = falco_real.observe(root_pid, since=since, timeout=timeout)
        return _build_observation(docker_out, artdir, report=report)
    finally:
        subprocess.run(["docker", "rm", "-f", "-v", name], capture_output=True)
        shutil.rmtree(artdir, ignore_errors=True)


def _read(artdir: str, fname: str, binary: bool = False):
    path = os.path.join(artdir, fname)
    if not os.path.exists(path):
        return None
    with open(path, "rb") as fh:
        data = fh.read()
    return data if binary else data.decode(errors="replace")


def _build_observation(docker_out: str, artdir: str, report: dict | None = None) -> tuple[ArenaObservation, dict]:
    """Build the observation from copied-out artifacts. ``report`` lets the
    real-Falco path (arena/run.py::_run_detailed_real_falco) supply behavioral
    facts sourced from the sensor instead of the in-container strace trace;
    when omitted (the default, unchanged path) it's parsed from trace.txt."""
    empty = {"syscalls": [], "files_written": 0, "encrypted_files": 0,
             "mean_entropy": 0.0, "write_paths": [], "network_attempts": 0}

    if "COMPILE_FAILED" in docker_out:
        err = (_read(artdir, "compile.err") or "compile failed").strip()
        return ArenaObservation(compiled=False, error=err[:400]), empty

    if report is None:
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
        files_written=report["files_written"], encrypted_files=report["encrypted_files"],
        mean_entropy=report["mean_entropy"], syscalls=report["syscalls"],
        stdout=stdout, exit_code=exit_code, error=error,
    )
    return obs, report


def _fake_run(source: str) -> ArenaObservation:
    """Deterministic stand-in so the loop runs without Docker. Reports the
    ransomware behavior unless the candidate was deliberately de-fanged."""
    disabled = BEHAVIOR_DISABLED_MARK in source
    # In fake mode we have no compiled ELF; stand in with the source bytes so the
    # signature detector (which keys on the embedded marker) still works.
    body = source.encode()
    sha = hashlib.sha256(body).hexdigest()
    if disabled:
        return ArenaObservation(
            compiled=True, binary_sha256=sha, binary_bytes=body,
            files_written=0, encrypted_files=0, mean_entropy=0.0,
            syscalls=["openat", "write"], stdout="hydra: behavior disabled", exit_code=0,
        )
    n = max(FILES_K + 14, 24)
    return ArenaObservation(
        compiled=True, binary_sha256=sha, binary_bytes=body,
        files_written=n, encrypted_files=n, mean_entropy=max(ENTROPY_H + 0.9, 7.9),
        syscalls=["openat", "write", "read", "unlink"],
        stdout="hydra: rewrote files, reversible, exiting clean", exit_code=0,
    )
