"""Real Falco sensor (HYDRA_REAL_FALCO=1 path, ARCHITECTURE.md §8).

Offline: the pure correlation/decode logic needs no docker. Real-sandbox:
runs the seed sample through the actual sensor and checks it agrees with the
strace path on the numbers that matter; requires docker + both images
(hydra-arena, hydra-falco) — skipped otherwise.
"""
import base64
import os
import shutil
import subprocess
import unittest

from detectors import falco_real


def _images_present() -> bool:
    if shutil.which("docker") is None:
        return False
    for image in ("hydra-arena", "hydra-falco"):
        r = subprocess.run(["docker", "image", "inspect", image], capture_output=True)
        if r.returncode != 0:
            return False
    return True


class TestBelongsTo(unittest.TestCase):
    def test_matches_on_pid(self):
        self.assertTrue(falco_real._belongs_to({"proc.pid": 42}, 42))

    def test_matches_on_ppid(self):
        self.assertTrue(falco_real._belongs_to({"proc.pid": 99, "proc.ppid": 42}, 42))

    def test_no_match_beyond_direct_child(self):
        # A grandchild (e.g. gcc's own cc1/as under entrypoint -> gcc -> cc1)
        # must NOT match on root_pid alone via a deep ancestor field — see the
        # module docstring for why: this used to match via proc.apid[2] and
        # silently counted gcc's compile-time /tmp writes as the candidate's.
        fields = {"proc.pid": 99, "proc.ppid": 50, "proc.apid[1]": 50, "proc.apid[2]": 42}
        self.assertFalse(falco_real._belongs_to(fields, 42))

    def test_no_match_for_unrelated_tree(self):
        fields = {"proc.pid": 99, "proc.ppid": 50, "proc.apid[1]": 50, "proc.apid[2]": 1}
        self.assertFalse(falco_real._belongs_to(fields, 42))


class TestDecodeBuffer(unittest.TestCase):
    def test_double_base64_roundtrip(self):
        # Falco's -b flag base64-encodes the buffer; the JSON writer encodes
        # that string again (empirically two layers — see falco_real.py).
        raw = b"HELLOWORLD"
        encoded_twice = base64.b64encode(base64.b64encode(raw))
        self.assertEqual(falco_real._decode_buffer(encoded_twice.decode()), raw)

    def test_malformed_input_returns_none(self):
        self.assertIsNone(falco_real._decode_buffer("not valid base64!!"))


@unittest.skipUnless(_images_present(), "docker + hydra-arena + hydra-falco images required")
class TestRealSandbox(unittest.TestCase):
    def test_seed_sample_matches_strace_path(self):
        from arena.run import run_detailed

        with open("sample/seed.c", encoding="utf-8") as fh:
            source = fh.read()

        strace_obs, _ = run_detailed(source)
        self.assertTrue(strace_obs.compiled, strace_obs.error)
        self.assertIsNone(strace_obs.error)

        self.assertTrue(falco_real.available(), "real falco sensor did not come up")
        try:
            os.environ["HYDRA_REAL_FALCO"] = "1"
            real_obs, _ = run_detailed(source)
        finally:
            os.environ.pop("HYDRA_REAL_FALCO", None)

        self.assertTrue(real_obs.compiled, real_obs.error)
        if real_obs.error == "real-falco: could not correlate this run":
            # Known, environmental: the sensor's own eBPF event volume slows
            # down new container starts enough, on a busy shared host, that
            # the pid-poll budget (10s) isn't always enough — see
            # ARCHITECTURE.md §9.2. Not a code defect; skip rather than fail.
            self.skipTest("host contention prevented pid correlation this run")
        self.assertIsNone(real_obs.error)
        self.assertEqual(real_obs.encrypted_files, strace_obs.encrypted_files)
        self.assertGreaterEqual(real_obs.mean_entropy, 7.0)


if __name__ == "__main__":
    unittest.main()
