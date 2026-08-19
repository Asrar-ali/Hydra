"""Mechanism-swap evasion: the key beat.

A behavioral rule that keys on the write()-in-place MECHANISM can be evaded
without abandoning the ransomware behavior — by replacing each victim via
write-to-temp + rename() instead of overwriting it in place. A rule that keys on
the OUTCOME (files end high-entropy, following rename) still catches it, and the
behavior-preservation gate confirms the behavior never stopped.

This breaks the old tautology (the rule and the gate keyed on the same fact, so
"evade while preserving behavior" was impossible by construction). Here they key
on different facts and can diverge — which is the whole point.

Runs without Docker: real strace-shaped text -> real arena.trace.parse() ->
ArenaObservation -> real detectors + gate.
"""
import unittest

from arena.trace import parse
from common.config import FILES_K
from common.contracts import ArenaObservation
from detectors import falco_detector
from referee.gate import behavior_preserved

N = FILES_K + 2  # comfortably above the bulk-encryption threshold

LOW = "".join(f"\\x{b:02x}" for b in b"A" * 256)          # entropy 0.0
HIGH = "".join(f"\\x{b:02x}" for b in bytes(range(256)))  # entropy 8.0


def _hex(s: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in s)


def _obs_from_trace(trace: str) -> ArenaObservation:
    r = parse(trace)
    return ArenaObservation(
        compiled=True,
        files_written=r["files_written"],
        encrypted_files=r["encrypted_files"],
        encrypted_in_place=r["encrypted_in_place"],
        encrypted_outcome=r["encrypted_outcome"],
        mean_entropy=r["mean_entropy"],
        syscalls=r["syscalls"],
    )


def _write_based_trace(n: int) -> str:
    """seed.c behavior: create victim w/ plaintext, then rewrite it IN PLACE
    with high-entropy content."""
    lines = []
    for i in range(n):
        v = _hex(f"/tmp/work/file_{i:02d}.dat".encode())
        lines += [
            f'openat(AT_FDCWD, "{v}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
            f'write(3, "{LOW}", 256) = 256',
            f'openat(AT_FDCWD, "{v}", O_WRONLY|O_TRUNC, 0666) = 3',
            f'write(3, "{HIGH}", 256) = 256',
        ]
    return "\n".join(lines)


def _rename_based_trace(n: int) -> str:
    """seed_rename.c behavior: plaintext to victim, ciphertext to a SIDE temp,
    then rename() the temp over the victim. The victim never gets a high-entropy
    write() — the destructive step is the rename."""
    lines = []
    for i in range(n):
        v = _hex(f"/tmp/work/file_{i:02d}.dat".encode())
        t = _hex(f"/tmp/work/file_{i:02d}.dat.tmp".encode())
        lines += [
            f'openat(AT_FDCWD, "{v}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
            f'write(3, "{LOW}", 256) = 256',
            f'openat(AT_FDCWD, "{t}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4',
            f'write(4, "{HIGH}", 256) = 256',
            f'rename("{t}", "{v}") = 0',
        ]
    return "\n".join(lines)


def _behavior_broken_trace(n: int) -> str:
    """Evades by ceasing to be malware: writes many files, encrypts none."""
    lines = []
    for i in range(n):
        v = _hex(f"/tmp/work/file_{i:02d}.dat".encode())
        lines += [
            f'openat(AT_FDCWD, "{v}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
            f'write(3, "{LOW}", 256) = 256',
        ]
    return "\n".join(lines)


class TestMechanismEvasion(unittest.TestCase):
    def test_write_based_both_rules_fire_behavior_preserved(self):
        obs = _obs_from_trace(_write_based_trace(N))
        self.assertEqual(obs.encrypted_in_place, N)
        self.assertEqual(obs.encrypted_outcome, N)
        self.assertEqual(falco_detector.evaluate_naive(obs), "FIRED")
        self.assertEqual(falco_detector.evaluate_robust(obs), "FIRED")
        self.assertTrue(behavior_preserved(obs))

    def test_rename_swap_evades_naive_but_not_robust_behavior_preserved(self):
        # The key beat: same behavior class, different mechanism.
        obs = _obs_from_trace(_rename_based_trace(N))
        self.assertEqual(obs.encrypted_in_place, 0)          # nothing overwritten in place
        self.assertEqual(obs.encrypted_outcome, N)           # every victim still ends encrypted
        self.assertEqual(falco_detector.evaluate_naive(obs), "SILENT")   # evaded
        self.assertEqual(falco_detector.evaluate_robust(obs), "FIRED")   # caught
        self.assertTrue(behavior_preserved(obs))             # behavior never stopped

    def test_breaking_behavior_evades_both_and_fails_the_gate(self):
        obs = _obs_from_trace(_behavior_broken_trace(N))
        self.assertEqual(obs.encrypted_outcome, 0)
        self.assertEqual(falco_detector.evaluate_naive(obs), "SILENT")
        self.assertEqual(falco_detector.evaluate_robust(obs), "SILENT")
        self.assertFalse(behavior_preserved(obs))            # evaded only by ceasing to be malware

    def test_rename_swap_is_a_real_evasion_not_a_behavior_change(self):
        # Contrast that makes the point: naive rule flips SILENT, gate does not.
        write_obs = _obs_from_trace(_write_based_trace(N))
        rename_obs = _obs_from_trace(_rename_based_trace(N))
        self.assertEqual(falco_detector.evaluate_naive(write_obs), "FIRED")
        self.assertEqual(falco_detector.evaluate_naive(rename_obs), "SILENT")
        self.assertTrue(behavior_preserved(write_obs))
        self.assertTrue(behavior_preserved(rename_obs))


if __name__ == "__main__":
    unittest.main()
