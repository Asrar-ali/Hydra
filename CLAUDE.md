# CLAUDE.md

Guidance for anyone — human or agent — working in this repo. Read
`ARCHITECTURE.md` first; it is the source of truth for design and interfaces.

Hydra is an adversarial evasion lab: a local LLM rewrites a benign,
ransomware-shaped sample to try to slip past two real detectors (YARA and Falco)
in a closed loop, and we measure how each detector holds up.

## Safety rules (non-negotiable)

- Generated or mutated code runs **only** inside the arena container
  (`--network=none`, resource- and time-limited, auto-removed). Never execute a
  candidate on the host.
- The sample stays benign: no network, no persistence, writes only the throwaway
  files it creates in its own working directory. Reject any change that adds
  capability.
- Real malware is **never executed** — static scanning only, and only where the
  architecture allows it.
- No secrets in the repo. Tokens and keys come from the environment or an
  untracked `.env`; `.env.example` holds placeholders only.

## Contributing

- Push directly to `main`. Keep commits small and focused so `main` always
  builds; pull before you push.
- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- Agree interfaces first, then code against the stubbed contracts so several
  people can work in parallel without collisions (see Working in parallel).
- Python, standard library first. Type hints, small focused modules, a logger
  (not `print`) in committed code.
- Validate input at boundaries (LLM output, subprocess results, arena
  observations). Fail closed on anything that violates a safety invariant.
- Run the safety test before you push anything touching the arena or the sample;
  it must pass. Keep `ARCHITECTURE.md` in sync when you change an interface (SSE
  contract, component paths, metrics).

## Working in parallel

Freeze the interfaces first — the arena observation shape (ARCHITECTURE.md §7),
the detector functions, `results.json` (§10), and the SSE contract (§11) — commit
them as stubs that return fake data, then each person owns a lane and codes
against those stubs:

| Lane | Owns | Files |
|---|---|---|
| 1 · Sandbox | arena container, seed sample, safety test | `sample/`, `arena/` |
| 2 · Detection | YARA + Falco detectors and rules | `detectors/` |
| 3 · Adversary | LLM rewriter (Ollama) + fallback mutator | `adversary/` |
| 4 · Integration & demo | referee loop, gate, metrics, server, dashboard; owns the shared contracts | `referee/`, `server.py`, `ui/` |

## Layout and run

See `ARCHITECTURE.md` §12 (repository layout), §13 (build order), and Appendix B
(how to run).
