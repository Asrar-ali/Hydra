#!/usr/bin/env python3
"""
Hydra PromptLock-mode seed — BENIGN BY CONSTRUCTION.

Same behavior contract as sample/seed.c (ARCHITECTURE.md §6), but for the
"runtime-generated payload" mode (ARCHITECTURE.md §9.3): in a live run the
referee asks a local LLM to generate a FRESH script like this one on every
execution (PromptLock-style, ESET Aug 2025) instead of reusing one compiled
binary. This file is the deterministic generation-0 baseline: it seeds the
signature rule and stands in when the LLM is unavailable.

Per run it:
  1. makes a private working directory under /tmp
  2. creates N files with known plaintext (low entropy)
  3. rewrites each in place with high-entropy content (simulated encryption)
  4. decrypts (XOR-reversible), removes the files and directory, exits 0

It never touches the network and writes only inside the directory it creates.
"""
import os
import tempfile

# Pin tempdir explicitly: tempfile's own lazy autodetection probes the
# candidate dir with a throwaway low-entropy write before first use, which
# would otherwise show up as a 25th (unencrypted) file in the trace.
tempfile.tempdir = "/tmp"

HYDRA_SIGNATURE = "HYDRA-SIGNATURE-000"

N_FILES = 24
FILE_SIZE = 4096
XOR_KEY = 0x5A


def _prng_byte(state):
    state = (state * 1103515245 + 12345) & 0xFFFFFFFF
    return state, (state >> 16) & 0xFF


def main():
    d = tempfile.mkdtemp(prefix="hydra_work_")
    state = 0x1234ABCD

    for i in range(N_FILES):
        path = os.path.join(d, "file_%02d.dat" % i)

        # 1) write known plaintext
        with open(path, "wb") as f:
            f.write(b"A" * FILE_SIZE)

        # 2) rewrite in place with high-entropy content (XOR-masked, reversible)
        buf = bytearray(FILE_SIZE)
        for j in range(FILE_SIZE):
            state, r = _prng_byte(state)
            buf[j] = r ^ XOR_KEY
        with open(path, "wb") as f:
            f.write(bytes(buf))

    # 3) decrypt to prove reversibility, then clean up
    for i in range(N_FILES):
        path = os.path.join(d, "file_%02d.dat" % i)
        with open(path, "rb") as f:
            data = f.read()
        bytes(b ^ XOR_KEY for b in data)  # decrypt (mirrors seed.c's XOR undo)
        os.remove(path)
    os.rmdir(d)

    print("hydra: %s: rewrote %d files, reversible, exiting clean" % (HYDRA_SIGNATURE, N_FILES))


if __name__ == "__main__":
    main()
