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

# Loop bounds.
ITERATION_CAP: int = int(os.environ.get("HYDRA_ITERATION_CAP", "12"))
ADV_ATTEMPTS: int = int(os.environ.get("HYDRA_ADV_ATTEMPTS", "3"))  # LLM retries per iteration

# Ollama / adversary.
OLLAMA_HOST: str = os.environ.get("HYDRA_OLLAMA_HOST", "http://127.0.0.1:11434")
ADVERSARY_MODEL: str = os.environ.get("HYDRA_ADVERSARY_MODEL", "jimscard/whiterabbit-neo")
