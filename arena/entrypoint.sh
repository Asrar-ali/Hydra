#!/bin/sh
# Arena entrypoint. Reads candidate C source from stdin, compiles it, runs it
# under strace, and leaves artifacts in /work for the host to copy out. Runs
# inside a throwaway, network-isolated container (see arena/run.py).
#
# Artifacts left in /work: candidate (binary), trace.txt, stdout.txt, exit.txt,
# compile.err. stdout of THIS script is OK / COMPILE_FAILED.
#
# HYDRA_NO_STRACE=1 skips the strace wrapper (no trace.txt): the real-Falco
# path (HYDRA_REAL_FALCO=1, arena/run.py) needs this — empirically, a process
# being ptrace-traced by strace stops showing up in Falco's eBPF probe at all,
# so the two capture mechanisms can't run on the same process at once. That
# path doesn't read trace.txt anyway; it gets its facts from the sensor.
set -u

SRC=/work/candidate.c
BIN=/work/candidate
cat > "$SRC"

if ! gcc -O0 -w -o "$BIN" "$SRC" 2>/work/compile.err; then
    echo COMPILE_FAILED
    exit 0
fi

if [ "${HYDRA_NO_STRACE:-}" = "1" ]; then
    "$BIN" >/work/stdout.txt 2>/work/run.err
else
    # -xx hex-encodes all string data; -s 4096 captures full write buffers so
    # the host can compute the entropy of what was actually written to disk.
    strace -f -xx -s 4096 \
        -e trace=openat,open,write,rename,renameat,renameat2,unlink,unlinkat,connect,socket,execve \
        -o /work/trace.txt "$BIN" >/work/stdout.txt 2>/work/run.err
fi
echo $? > /work/exit.txt
echo OK
