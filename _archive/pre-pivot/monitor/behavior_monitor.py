"""
Hydra — behavior monitor.

Runs a sample in a fresh, isolated temp directory and fingerprints its
OBSERVABLE EFFECTS — what it prints and what files it creates (by content) —
rather than its bytes. Because every generation performs the exact same
actions, the behavioral fingerprint is identical across all of them.

This is the honest, cross-platform version of "watch what it does": we
observe the effects independently (not self-reported). On Linux you could
swap in strace/eBPF for a syscall-level trace; the effect fingerprint below
is invariant regardless and needs no privileges.
"""
import hashlib
import os
import subprocess
import tempfile


def fingerprint(binary_path: str, timeout: float = 5.0) -> dict:
    """Run the sample in a sandbox dir; return an effects fingerprint."""
    with tempfile.TemporaryDirectory(prefix="hydra_sbx_") as sbx:
        before = set(os.listdir(sbx))
        try:
            proc = subprocess.run(
                [os.path.abspath(binary_path)],
                cwd=sbx,
                capture_output=True,
                timeout=timeout,
            )
            stdout = proc.stdout.decode("utf-8", "replace").strip()
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            stdout, rc = "<timeout>", -1

        created = []
        for name in sorted(set(os.listdir(sbx)) - before):
            try:
                with open(os.path.join(sbx, name), "rb") as fh:
                    content_hash = hashlib.sha256(fh.read()).hexdigest()[:12]
            except OSError:
                content_hash = "unreadable"
            created.append(f"{name}:{content_hash}")

    canonical = f"stdout={stdout}|exit={rc}|files={','.join(created)}"
    fp = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    return {
        "fingerprint": fp,
        "stdout": stdout,
        "exit": rc,
        "files": created,
        "canonical": canonical,
    }
