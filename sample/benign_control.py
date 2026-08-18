#!/usr/bin/env python3
"""
Benign control for PromptLock mode — writes many files but is NOT ransomware.

Mirrors sample/benign_control.c for the promptlock sandbox. It creates more
files than the detector's file-count threshold but fills them with low-entropy
plaintext, so the bulk-encryption signal is absent and the behavioral detector
must stay SILENT. A detector that fired here would be flagging "writes files",
not "encrypts files".

Benign by construction: own temp dir under /tmp, no network, no persistence,
cleaned up on exit.
"""
import os
import tempfile

tempfile.tempdir = "/tmp"

N_FILES = 12


def main():
    d = tempfile.mkdtemp(prefix="hydra_ctl_")
    for i in range(N_FILES):
        path = os.path.join(d, "log_%02d.txt" % i)
        with open(path, "w") as f:
            for k in range(200):
                f.write("log entry %d: all systems ok\n" % i)
        os.remove(path)
    os.rmdir(d)
    print("control: wrote %d plaintext log files" % N_FILES)


if __name__ == "__main__":
    main()
