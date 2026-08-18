"""Arena — compile and run one candidate, return an ArenaObservation.

Lane 1 owns this file. The real path runs the candidate inside a throwaway,
network-isolated container (see arena/Dockerfile, arena/entrypoint.sh) and
parses a syscall trace. Until that lands, ``fake=True`` (or HYDRA_FAKE=1)
returns a deterministic observation so the rest of the pipeline is runnable.

Contract: ``run(source: str) -> ArenaObservation``. See ARCHITECTURE.md §7, §8.
"""
from __future__ import annotations

import hashlib
import os

from common.config import ENTROPY_H, FILES_K
from common.contracts import ArenaObservation
from common.logging import get_logger

log = get_logger("arena")

# Fake-mode marker: the offline mutator adds this when it "breaks behavior" for
# the finale, so the fake arena can report a non-ransomware run. The REAL arena
# ignores this and reports what actually happened.
BEHAVIOR_DISABLED_MARK = "HYDRA_BEHAVIOR_DISABLED"


def run(source: str, *, fake: bool | None = None, timeout: float = 10.0) -> ArenaObservation:
    if fake is None:
        fake = os.environ.get("HYDRA_FAKE") == "1"
    if fake:
        return _fake_run(source)
    return _container_run(source, timeout=timeout)


def _fake_run(source: str) -> ArenaObservation:
    """Deterministic stand-in so the loop runs without Docker. Reports the
    ransomware behavior unless the source was deliberately de-fanged."""
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
        syscalls=["openat", "write", "openat", "read", "write", "unlink"],
        stdout="hydra: rewrote files, reversible, exiting clean", exit_code=0,
    )


def _container_run(source: str, *, timeout: float) -> ArenaObservation:
    # TODO(lane1): build the arena image (`make arena-build`), then:
    #   1. write `source` to a private dir
    #   2. `docker run --rm --network=none --read-only --tmpfs /tmp ...
    #       --memory=256m --pids-limit=128 hydra-arena` with the source piped in
    #   3. entrypoint.sh compiles, runs under strace, prints one JSON line
    #   4. parse it into ArenaObservation; enforce the safety invariants (§6)
    raise NotImplementedError(
        "Real arena not wired yet. Build the image and implement _container_run, "
        "or run with HYDRA_FAKE=1 for pipeline wiring. See ARCHITECTURE.md §8."
    )
