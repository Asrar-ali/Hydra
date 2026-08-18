"""Safety test — the sandbox invariants (ARCHITECTURE.md §6, §10).

Gating before any demo. Requires Docker + the built arena image; skipped
otherwise so the rest of the suite still runs. Build the image with
``make arena-build``.
"""
import shutil
import subprocess
import unittest

from common.config import FILES_K


def _image_present() -> bool:
    if shutil.which("docker") is None:
        return False
    r = subprocess.run(["docker", "image", "inspect", "hydra-arena"], capture_output=True)
    return r.returncode == 0


@unittest.skipUnless(_image_present(), "docker + hydra-arena image required")
class TestSafety(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from arena.run import run_detailed  # imported lazily so skip works without docker

        with open("sample/seed.c", encoding="utf-8") as fh:
            source = fh.read()
        cls.obs, cls.report = run_detailed(source)

    def test_compiles_and_runs_clean(self):
        self.assertTrue(self.obs.compiled)
        self.assertEqual(self.obs.exit_code, 0)
        self.assertIsNone(self.obs.error)

    def test_exhibits_the_behavior_class(self):
        self.assertGreaterEqual(self.obs.files_written, FILES_K)
        self.assertGreaterEqual(self.obs.mean_entropy, 7.0)

    def test_no_network_syscalls(self):
        self.assertEqual(self.report["network_attempts"], 0)

    def test_all_writes_confined_to_sandbox(self):
        outside = [p for p in self.report["write_paths"] if not p.startswith("/tmp/")]
        self.assertEqual(outside, [], f"writes escaped the sandbox: {outside}")

    def test_container_removed(self):
        r = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"],
                           capture_output=True, text=True)
        leftovers = [n for n in r.stdout.split() if n.startswith("hydra_run_")]
        self.assertEqual(leftovers, [], f"leftover containers: {leftovers}")


if __name__ == "__main__":
    unittest.main()
