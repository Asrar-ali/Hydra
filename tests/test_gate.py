"""Behavior-preservation gate + behavioral detector agree on the class."""
import unittest

from common.config import ENTROPY_H, FILES_K
from common.contracts import ArenaObservation
from detectors import falco_detector
from referee.gate import behavior_preserved


def _obs(files, entropy, compiled=True):
    return ArenaObservation(compiled=compiled, files_written=files, mean_entropy=entropy)


class TestGate(unittest.TestCase):
    def test_ransomware_shaped_run_fires_and_is_preserved(self):
        obs = _obs(FILES_K + 5, ENTROPY_H + 0.5)
        self.assertTrue(behavior_preserved(obs))
        self.assertEqual(falco_detector.evaluate(obs), "FIRED")

    def test_defanged_run_is_silent_and_not_preserved(self):
        obs = _obs(0, 0.0)
        self.assertFalse(behavior_preserved(obs))
        self.assertEqual(falco_detector.evaluate(obs), "SILENT")

    def test_non_compiling_is_silent(self):
        self.assertEqual(falco_detector.evaluate(_obs(50, 8.0, compiled=False)), "SILENT")


if __name__ == "__main__":
    unittest.main()
