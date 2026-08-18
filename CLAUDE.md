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

- Branch before editing: `feat/…`, `fix/…`, `chore/…`. Do not commit to `main`
  directly.
- Conventional commits: `feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`.
- Never push without explicit approval.
- Python, standard library first. Type hints, small focused modules, a logger
  (not `print`) in committed code.
- Validate input at boundaries (LLM output, subprocess results, arena
  observations). Fail closed on anything that violates a safety invariant.
- Run the safety test before any change touching the arena or the sample; it must
  pass. Keep `ARCHITECTURE.md` in sync when you change an interface (SSE contract,
  component paths, metrics).

## Layout and run

See `ARCHITECTURE.md` §12 (repository layout), §13 (build order), and Appendix B
(how to run).
