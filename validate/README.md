# validate/ — real-malware rule validation (optional, gated)

Static-only checks that the detection rules fire on **real** ransomware, so the
rules aren't tuned only to our own sample. Samples are **never executed** — YARA
scans bytes statically, in an isolated context, and only if sample handling is
approved. See ARCHITECTURE.md §9.3. Nothing here runs by default.
