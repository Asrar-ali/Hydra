Pre-pivot code, moved aside 2026-08-18. `engine/`, `scanner/`, `monitor/`,
`run_demo.py` are the design that came before the arena/detectors/adversary/
referee split (see git log before the promptlock-mode and real-Falco work).
Different module names, different tagline ("You can't sign what won't hold
still."), no promptlock mode, no real Falco. Nothing in the current codebase
imports or references these. Kept here instead of deleted since they were
never committed to git; safe to delete for real once someone's sure nothing
in `pitch/pitch.html` or `plan/hydra-architecture.html` still needs updating
against them.
