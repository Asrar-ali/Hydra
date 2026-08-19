"""
Hydra — optional LLM mutation path (the "AI-first" headline).

Sends the current C source to an OpenAI-compatible chat endpoint and asks for
a semantically-equivalent rewrite. Uses only the Python standard library so
there are no dependencies to install. Configure via environment:

    HYDRA_LLM_BASE   e.g. https://your-endpoint/v1   (chat/completions is appended)
    HYDRA_LLM_KEY    bearer token
    HYDRA_LLM_MODEL  model name (default: gpt-4o-mini)

If unset or anything fails, the caller falls back to the offline engine, so
the demo always works. The LLM only ever rewrites BENIGN code.
"""
import json
import os
import urllib.request

REWRITE_PROMPT = """You are a metamorphic-code engine used in a DEFENSIVE security demo.
Rewrite the following C program so that it is byte-for-byte DIFFERENT from the input
but FUNCTIONALLY IDENTICAL (same stdout, same files written, same behavior).

Transform aggressively but safely:
- rename every function and variable
- reorder independent function definitions
- swap equivalent control structures (loops <-> recursion, if <-> ternary/switch)
- change how the constant strings are stored/encoded (still decoded at runtime)
- insert semantically-neutral junk (unused functions/vars, dead statements)
- vary formatting

Hard rules: it MUST compile with a standard C compiler and MUST NOT add any new
observable behavior (no new files, no network, no new output). Output ONLY the
complete C source, no markdown, no commentary.

--- SOURCE ---
%s
--- END SOURCE ---"""


def is_configured() -> bool:
    return bool(os.environ.get("HYDRA_LLM_BASE") and os.environ.get("HYDRA_LLM_KEY"))


def rewrite(source: str, timeout: float = 60.0) -> str:
    base = os.environ["HYDRA_LLM_BASE"].rstrip("/")
    key = os.environ["HYDRA_LLM_KEY"]
    model = os.environ.get("HYDRA_LLM_MODEL", "gpt-4o-mini")
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": REWRITE_PROMPT % source}],
        "temperature": 1.0,
    }
    req = urllib.request.Request(
        base + "/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    text = data["choices"][0]["message"]["content"].strip()
    # strip accidental markdown fences
    if text.startswith("```"):
        text = text.split("\n", 1)[1] if "\n" in text else text
        if text.endswith("```"):
            text = text.rsplit("```", 1)[0]
        text = text.replace("```c", "").replace("```", "").strip()
    return text
