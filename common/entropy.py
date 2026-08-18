"""Shannon entropy helper (bits per byte, 0..8). Used to decide whether written
file content looks 'encrypted' (high entropy) — the core of the behavior class."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
