#!/bin/sh
# PromptLock-mode arena entrypoint. Reads a freshly generated Python script
# from stdin and runs it under strace — no compile step, since the candidate
# itself IS the runtime-generated payload (see ARCHITECTURE.md §9.3). Selected
# at container start via `docker run --entrypoint` (arena/run.py); the image's
# default entrypoint (entrypoint.sh) still handles compiled-C candidates.
#
# Leaves the same artifact shapes as entrypoint.sh so the host-side observation
# builder (arena/run.py::_build_observation) needs no mode-specific parsing:
# candidate (script bytes), trace.txt, stdout.txt, exit.txt. No compile.err /
# COMPILE_FAILED path exists for this mode.
set -u

SRC=/work/candidate.py
BIN=/work/candidate
cat > "$SRC"
cp "$SRC" "$BIN"

# -B / PYTHONDONTWRITEBYTECODE: skip .pyc caching — the image root is
# read-only outside /work and /tmp, so a cache write would just fail; this
# avoids the noise. -xx / -s 4096 as in entrypoint.sh: full write-buffer
# capture so the host can compute entropy of what was actually written.
strace -f -xx -s 4096 \
    -e trace=openat,open,write,unlink,unlinkat,connect,socket,execve \
    -o /work/trace.txt env PYTHONDONTWRITEBYTECODE=1 python3 -B "$SRC" >/work/stdout.txt 2>/work/run.err
echo $? > /work/exit.txt
echo OK
