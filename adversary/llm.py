"""LLM adversary — rewrite a candidate to evade a detector, via a local model
(WhiteRabbitNeo) served by Ollama. Lane 3 owns this.

Offline and $0. The prompt constrains the model to a behavior-preserving rewrite
of a benign C program and forbids adding capability. The referee validates every
rewrite in the arena (compiles? behavior preserved?) and retries with the failure
as feedback, so the model adapts — what a template mutator cannot do.

Contract:
    is_available() -> bool
    rewrite(feedback: Feedback) -> str                 # one-shot
    rewrite_stream(feedback: Feedback) -> Iterator[str] # yields tokens (for SSE)
    extract_c(text: str) -> str

Promptlock mode (ARCHITECTURE.md §9.3) generates a fresh script per call instead
of rewriting from feedback — same model, a different prompt and output language:
    generate_promptlock(iteration: int) -> str
    generate_promptlock_stream(iteration: int) -> Iterator[str]
    extract_py(text: str) -> str
"""
from __future__ import annotations

import json
import urllib.request
from typing import Iterator

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


def _messages(feedback: Feedback, system: str | None = None) -> list[dict]:
    user = (
        f"Detector: {feedback.detector}\n"
        f"Why it was flagged:\n{feedback.reason}\n\n"
        f"Current program:\n{feedback.source}\n\n"
        "Return the full rewritten C program only."
    )
    return [{"role": "system", "content": system or _SYSTEM}, {"role": "user", "content": user}]


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


def rewrite(feedback: Feedback, timeout: float = 180.0, temperature: float = 0.4,
            system: str | None = None) -> str:
    """One-shot rewrite (no streaming)."""
    payload = {"model": ADVERSARY_MODEL, "messages": _messages(feedback, system),
               "stream": False, "options": {"temperature": temperature}}
    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return extract_c(data["message"]["content"])


def rewrite_stream(feedback: Feedback, timeout: float = 180.0,
                   temperature: float = 0.4,
                   system: str | None = None) -> Iterator[str]:
    """Yield content tokens as the model writes. Caller accumulates and calls
    ``extract_c`` on the full text."""
    payload = {"model": ADVERSARY_MODEL, "messages": _messages(feedback, system),
               "stream": True, "options": {"temperature": temperature}}
    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for raw in resp:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            piece = obj.get("message", {}).get("content", "")
            if piece:
                yield piece
            if obj.get("done"):
                break


_SYSTEM_PROMPTLOCK = (
    "You are generating a FRESH, BENIGN Python 3 script for an authorized "
    "detector-robustness lab. It mimics how AI-generated ransomware (PromptLock, "
    "ESET Aug 2025) produces a brand-new script at every execution instead of "
    "reusing one binary. The script, when run, must: "
    "1) create a private temp directory under /tmp (set tempfile.tempdir = \"/tmp\" "
    "before calling tempfile.mkdtemp, so its own directory-probe write doesn't "
    "appear as an extra untouched file); "
    "2) create at least 24 files there containing plaintext bytes; "
    "3) rewrite each file in place with high-entropy pseudo-random bytes, using a "
    "fixed key so the transform is reversible; "
    "4) decrypt every file back with that key to prove reversibility; "
    "5) delete the files and the directory; "
    "6) print one line, then exit 0. "
    "Never touch the network, never call subprocess/os.system/eval, never write "
    "outside the directory it creates. Use ONLY the Python standard library. "
    "Every script you generate must be structurally and lexically DIFFERENT from "
    "any other: different variable/function names, different directory-name "
    "prefix, different control flow, different string literals. Output ONLY the "
    "complete Python script — no prose, no markdown fences."
)


def _promptlock_messages(iteration: int, system: str | None = None) -> list[dict]:
    user = (
        f"Generate script #{iteration}. Make it look like a different author wrote "
        "it than any previous run: new names, new structure, new strings. Return "
        "the full Python script only."
    )
    return [{"role": "system", "content": system or _SYSTEM_PROMPTLOCK}, {"role": "user", "content": user}]


def generate_promptlock(iteration: int, timeout: float = 180.0, temperature: float = 0.9,
                        system: str | None = None) -> str:
    """One-shot: a freshly GENERATED PromptLock-style script (not a rewrite of a
    prior candidate — a new script per call, per ARCHITECTURE.md §9.3)."""
    payload = {"model": ADVERSARY_MODEL, "messages": _promptlock_messages(iteration, system),
               "stream": False, "options": {"temperature": temperature}}
    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read())
    return extract_py(data["message"]["content"])


def generate_promptlock_stream(iteration: int, timeout: float = 180.0,
                               temperature: float = 0.9,
                               system: str | None = None) -> Iterator[str]:
    """Streaming form of ``generate_promptlock`` (for SSE)."""
    payload = {"model": ADVERSARY_MODEL, "messages": _promptlock_messages(iteration, system),
               "stream": True, "options": {"temperature": temperature}}
    req = urllib.request.Request(
        f"{OLLAMA_HOST}/api/chat", data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        for raw in resp:
            raw = raw.strip()
            if not raw:
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError:
                continue
            piece = obj.get("message", {}).get("content", "")
            if piece:
                yield piece
            if obj.get("done"):
                break


def extract_py(text: str) -> str:
    """Pull Python source out of the model's reply (handles fences / stray prose)."""
    text = text.strip()
    if "```" in text:
        blocks = text.split("```")[1::2]
        if blocks:
            block = max(blocks, key=len)
            if "\n" in block:
                first, rest = block.split("\n", 1)
                block = rest if first.strip().lower() in ("py", "python", "python3") else block
            return block.strip()
    for marker in ("#!/usr/bin/env python", "import ", "from ", "def main"):
        idx = text.find(marker)
        if idx != -1:
            return text[idx:].strip()
    return text


def extract_c(text: str) -> str:
    """Pull C source out of the model's reply (handles fences / stray prose)."""
    text = text.strip()
    if "```" in text:
        blocks = text.split("```")[1::2]
        if blocks:
            block = max(blocks, key=len)
            if "\n" in block:
                first, rest = block.split("\n", 1)
                block = rest if first.strip().lower() in ("c", "cpp", "c++") else block
            return block.strip()
    for marker in ("#include", "/*", "int main", "static "):
        idx = text.find(marker)
        if idx != -1:
            return text[idx:].strip()
    return text


# Back-compat alias used by tests.
_extract_c = extract_c
