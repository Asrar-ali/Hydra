#!/bin/sh
# Arena entrypoint. Reads candidate C source from stdin, compiles it, runs it
# under strace, and prints ONE JSON line describing what happened. Runs inside a
# throwaway, network-isolated container (see arena/run.py).
#
# TODO(lane1): finish the JSON emission (files_written, mean_entropy from the
# work dir, unique syscalls from the trace) and have arena/run.py parse it.
set -eu

SRC=/work/candidate.c
BIN=/work/candidate
cat > "$SRC"

if ! gcc -O0 -w -o "$BIN" "$SRC" 2> /work/compile.err; then
    printf '{"compiled":false,"error":%s}\n' "$(sed 's/"/\\"/g' /work/compile.err | head -c 400 | sed 's/.*/"&"/')"
    exit 0
fi

# -f follow children; capture file + process syscalls relevant to the behavior class
strace -f -e trace=openat,open,write,read,unlink,unlinkat,connect,socket \
    -o /work/trace.txt "$BIN" > /work/stdout.txt 2>/dev/null || true

# Minimal placeholder emission; real parsing done in Python for now.
printf '{"compiled":true,"trace":"/work/trace.txt","stdout_file":"/work/stdout.txt"}\n'
