# sample/

`seed.c` — the benign, ransomware-shaped starting point (generation 0) that the
adversary mutates and the detectors judge.

**It is safe by construction.** It only ever touches throwaway files it creates
in its own temp directory, does no network or persistence, and reverses its own
"encryption" before exiting. It exists to exhibit the *behavior class* real
detectors target (many files rewritten with high-entropy content), so the
behavioral detector has something real to catch. See ARCHITECTURE.md §6.

Any change here must keep the safety invariants in ARCHITECTURE.md §6 and pass
the safety test before it is pushed.
