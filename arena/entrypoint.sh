#!/bin/sh
# Arena entrypoint. Reads candidate C source from stdin, compiles it, runs it
# under strace, and leaves artifacts in /work for the host to copy out. Runs
# inside a throwaway, network-isolated container (see arena/run.py).
#
# Artifacts left in /work: candidate (binary), trace.txt, stdout.txt, exit.txt,
# compile.err. stdout of THIS script is OK / COMPILE_FAILED.
set -u

SRC=/work/candidate.c
BIN=/work/candidate
cat > "$SRC"

if ! gcc -O0 -w -o "$BIN" "$SRC" 2>/work/compile.err; then
    echo COMPILE_FAILED
    exit 0
fi

# -xx hex-encodes all string data; -s 4096 captures full write buffers so the
# host can compute the entropy of what was actually written to disk.
strace -f -xx -s 4096 \
    -e trace=openat,open,write,unlink,unlinkat,connect,socket,execve \
    -o /work/trace.txt "$BIN" >/work/stdout.txt 2>/work/run.err
echo $? > /work/exit.txt
echo OK
