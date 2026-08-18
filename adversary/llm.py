"""LLM adversary — rewrite a candidate to evade a detector, via a local model
(WhiteRabbitNeo) served by Ollama. Lane 3 owns this.

Offline and $0. The prompt constrains the model to a behavior-preserving rewrite
of a benign C program and forbids adding capability. The referee validates every
rewrite in the arena (compiles? behavior preserved?) and retries with the failure
as feedback, so the model adapts — this is what a template mutator cannot do.

Contract:
    is_available() -> bool
    rewrite(feedback: Feedback) -> str   (returns C source)
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
    "You are a red-team code transformer in an authorized detector-robustness lab. "
    "You receive a BENIGN C program and the reason a lab detector flagged it. "
    "Rewrite the program so it no longer triggers that detector, while keeping its "
    "observable behavior IDENTICAL: it must still create and then rewrite the same "
    "number of files with the same high-entropy content in a temp directory, and "
    "print a line. Do NOT add any capability (no network, no persistence, no new "
    "file locations). Rename identifiers, change string constants, reorder and "
    "restructure code as needed. Output ONLY compilable C — no prose, no markdown."
)


def _post(path: str, payload: dict, timeout: float) -> dict:
    req = urllib.request.Request(
        f"{OLLAMA_HOST}{path}", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def is_available(timeout: float = 2.0) -> bool:
    """True only if Ollama is up AND the configured model is present."""
    try:
        req = urllib.request.Request(f"{OLLAMA_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            tags = json.loads(resp.read()).get("models", [])
    except Exception as exc:  # noqa: BLE001 - availability probe
        log.warning("ollama not reachable: %s", exc)
        return False
    names = {m.get("name", "") for m in tags}
    if any(n == ADVERSARY_MODEL or n.startswith(ADVERSARY_MODEL + ":") for n in names):
        return True
    log.warning("model %r not pulled (have: %s)", ADVERSARY_MODEL, ", ".join(sorted(names)))
    return False


def rewrite(feedback: Feedback, timeout: float = 180.0, temperature: float = 0.4) -> str:
    """Ask the model to evade ``feedback.detector`` while preserving behavior."""
    user = (
        f"Detector: {feedback.detector}\n"
        f"Why it was flagged:\n{feedback.reason}\n\n"
        f"Current program:\n{feedback.source}\n\n"
        "Return the full rewritten C program only."
    )
    data = _post("/api/chat", {
        "model": ADVERSARY_MODEL,
        "messages": [{"role": "system", "content": _SYSTEM},
                     {"role": "user", "content": user}],
        "stream": False,
        "options": {"temperature": temperature},
    }, timeout)
    return _extract_c(data["message"]["content"])


def _extract_c(text: str) -> str:
    """Pull C source out of the model's reply (handles fences / stray prose)."""
    text = text.strip()
    if "```" in text:
        # take the largest fenced block
        parts = text.split("```")
        blocks = [b for b in parts[1::2]]
        if blocks:
            block = max(blocks, key=len)
            if "\n" in block:  # drop an optional language tag on the first line
                first, rest = block.split("\n", 1)
                block = rest if first.strip().lower() in ("c", "cpp", "c++") else block
            return block.strip()
    # no fences: keep from the first preprocessor/comment/type token to the end
    for marker in ("#include", "/*", "int main", "static "):
        idx = text.find(marker)
        if idx != -1:
            return text[idx:].strip()
    return text
