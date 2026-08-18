"""LLM adversary — rewrite a candidate to evade a detector, via a local model
(WhiteRabbitNeo) served by Ollama. Lane 3 owns this.

Offline and $0. The prompt constrains the model to a behavior-preserving rewrite
of the supplied benign source and forbids adding capability. If Ollama or the
model is unavailable, the referee falls back to the deterministic mutator.

Contract: rewrite(feedback: Feedback) -> str   (returns C source)
"""
from __future__ import annotations

import json
import urllib.request

from common.config import ADVERSARY_MODEL, OLLAMA_HOST
from common.contracts import Feedback, Provenance
from common.logging import get_logger

log = get_logger("adversary")

provenance: Provenance = "llm"

_SYSTEM = (
    "You are a red-team code transformer used in an authorized detector-robustness "
    "lab. You are given a BENIGN C program and a reason it was flagged by a lab "
    "detector. Rewrite the program so it no longer triggers that detector, while "
    "keeping its observable behavior IDENTICAL. Do not add any new capability "
    "(no network, no persistence, no new file targets). Output ONLY C source."
)


def is_available(timeout: float = 2.0) -> bool:
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=timeout):
            return True
    except Exception as exc:  # noqa: BLE001 - availability probe
        log.warning("ollama not available (%s): %s", ADVERSARY_MODEL, exc)
        return False


def rewrite(feedback: Feedback, timeout: float = 120.0) -> str:
    """Ask the model to evade ``feedback.detector`` while preserving behavior."""
    prompt = (
        f"{_SYSTEM}\n\n--- reason it was caught ({feedback.detector}) ---\n"
        f"{feedback.reason}\n\n--- current source ---\n{feedback.source}\n\n"
        "Rewritten C source:"
    )
    body = json.dumps({"model": ADVERSARY_MODEL, "prompt": prompt, "stream": False}).encode()
    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/generate", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        out = json.loads(resp.read())["response"]
    return _strip_fences(out)

    # TODO(lane3): add a streaming variant (stream=True) that yields tokens for
    # the SSE dashboard, and validate/repair non-compiling output before return.


def _strip_fences(text: str) -> str:
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
    return text.strip()
