# Hydra

**An adversarial evasion lab.** A local, security-tuned LLM rewrites a benign,
ransomware-shaped program to try to slip past two real detectors — YARA
(signature) and Falco (behavioral) — in a closed loop. We measure how each holds
up. The result is a number, not a scripted reveal: the signature detector is
evaded in a few iterations; the behavioral detector is not evaded at all while
the sample still behaves like malware.

> Kill one signature, it grows a new head.

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the full design and
**[CLAUDE.md](CLAUDE.md)** for safety rules and how to contribute.

## Safety

The sample is benign by construction: it only rewrites throwaway files it creates
in its own sandbox, does no network or persistence, and reverses its own
"encryption" before exiting. Mutated code runs only inside a throwaway,
network-isolated container. Real malware is never executed. See ARCHITECTURE.md §6.

## Quickstart

Runs today with a fake arena, so you can see the whole loop with **no** container,
model, or detector installed:

```bash
git clone https://github.com/Asrar-ali/Hydra.git && cd Hydra
make run        # HYDRA_FAKE=1 — runs the loop, writes results.json, self-checks
make test       # unit tests (stdlib unittest, no deps)
make dashboard  # http://localhost:8000/  ->  ▶ Run
```

For the real pipeline: `make setup` (installs yara, pulls the model), then
`make arena-build`, then run without `HYDRA_FAKE`.

The default model is `mistral:7b` — fast (~30s/iteration) and reliable: it
clears the signature rule cleanly, usually in one iteration. The original
on-theme pick, `jimscard/whiterabbit-neo` (13B), turned out not to be able to
finish Track 1 at all: given the exact leftover strings and told directly,
three different ways, to reword them, it fixed 2 of 4 and then produced the
same output for 5 straight rounds, permanently stuck 1 needle above the
evasion threshold (verified 2026-08-18 — see `common/config.py`). It's still
available via `HYDRA_ADVERSARY_MODEL=jimscard/whiterabbit-neo`, on-theme but a
real risk of never evading live. A much smaller model like `llama3.2:1b` is
fast but too weak in a different way — most iterations fall through to the
deterministic mutator instead of the LLM, so it isn't a good demo substitute
either.

## Two payload modes

- **metamorphic** (default) — the LLM rewrites one C program between builds,
  reacting to detector feedback each time. `make run`
- **promptlock** — modeled on the PromptLock ransomware (ESET, Aug 2025): the
  LLM writes a brand-new Python script every single run instead of reusing one
  binary. No feedback loop, just a fresh script each time. `make run-promptlock`

Same story either way: the signature rule dies, the behavioral rule doesn't.
Toggle it in the dashboard or pass `--mode promptlock` to `referee/loop.py`.

## Real Falco (optional)

By default the behavioral facts come from strace, run inside the sandbox.
There's also a real Falco/eBPF sensor (`make falco-build`, then
`HYDRA_REAL_FALCO=1`) — same rule, real syscalls instead of a trace parse.
It's opt-in, not the default: it needs a privileged, host-wide container, and
on a busy shared machine it can be slow enough to time out. Don't turn it on
for a live demo. Details and the gotchas we hit: ARCHITECTURE.md §9.2.

## Layout

```
common/       shared contracts, config, logging, entropy      (import from here)
sample/       seed.c / seed_promptlock.py — the benign sample  (Lane 1)
arena/        throwaway-container compile/run + capture         (Lane 1)
detectors/    yara (signature) + falco (behavioral) + rules     (Lane 2)
adversary/    llm.py (Ollama) + mutator.py (fallback)           (Lane 3)
referee/      loop.py + gate.py — the loop, the metrics         (Lane 4)
server.py     HTTP + SSE dashboard server                       (Lane 4)
ui/           index.html — SSE dashboard                         (Lane 4)
tests/        unit tests
```

## Working on it

Pick a lane (see the table in [CLAUDE.md](CLAUDE.md)). Everything talks through
the contracts in `common/contracts.py`, so lanes can be built in parallel against
the fake arena and wired to the real tools independently.
