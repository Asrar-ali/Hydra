"""Tunable constants shared across lanes.

The behavioral thresholds (K, H) define what "ransomware-shaped" means for both
the Falco rule and the behavior-preservation gate. They are here, in one place,
so the detector and the gate can never drift apart. See ARCHITECTURE.md §5.1.
"""
from __future__ import annotations

import os

# Behavior class: "rewrites many files with high-entropy content".
FILES_K: int = int(os.environ.get("HYDRA_FILES_K", "10"))        # min files rewritten
ENTROPY_H: float = float(os.environ.get("HYDRA_ENTROPY_H", "7.0"))  # min mean bits/byte

# The `rate_windowed` rule (arena/trace.py, detectors/rules_registry.py) keys
# on >= FILES_K victims encrypted within this many seconds; the throttle
# mechanism evades it by sleeping longer than this between victims.
RATE_WINDOW_SECONDS: float = float(os.environ.get("HYDRA_RATE_WINDOW", "2.0"))

# Loop bounds.
ITERATION_CAP: int = int(os.environ.get("HYDRA_ITERATION_CAP", "12"))
ADV_ATTEMPTS: int = int(os.environ.get("HYDRA_ADV_ATTEMPTS", "3"))  # LLM retries per iteration

# Ollama / adversary.
OLLAMA_HOST: str = os.environ.get("HYDRA_OLLAMA_HOST", "http://127.0.0.1:11434")
# jimscard/whiterabbit-neo (13B) was the on-theme original default, but it
# provably can't finish Track 1: fed the exact needles left over and told
# explicitly, three different ways, to reword them, it fixed 2 of 4 and then
# sat on the same 2 for 5 straight rounds with zero further change (verified
# 2026-08-18). mistral:7b clears all 4 in a single iteration and is faster.
ADVERSARY_MODEL: str = os.environ.get("HYDRA_ADVERSARY_MODEL", "mistral:7b")
