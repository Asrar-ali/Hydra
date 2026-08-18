"""Specificity test — a benign program that writes many files must NOT fire the
behavioral detector. Requires Docker + the arena image; skipped otherwise."""
import shutil
import subprocess
import unittest

from detectors import falco_detector
from referee.gate import behavior_preserved


def _image_present() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "image", "inspect", "hydra-arena"],
                          capture_output=True).returncode == 0


@unittest.skipUnless(_image_present(), "docker + hydra-arena image required")
class TestControl(unittest.TestCase):
    def test_benign_multifile_writer_does_not_fire(self):
        from arena.run import run_detailed

        with open("sample/benign_control.c", encoding="utf-8") as fh:
            obs, _ = run_detailed(fh.read())
        self.assertTrue(obs.compiled, obs.error)
        self.assertGreaterEqual(obs.files_written, 10)     # it DID write many files
        self.assertEqual(obs.encrypted_files, 0)           # but encrypted none
        self.assertEqual(falco_detector.evaluate(obs), "SILENT")
        self.assertFalse(behavior_preserved(obs))


if __name__ == "__main__":
    unittest.main()
