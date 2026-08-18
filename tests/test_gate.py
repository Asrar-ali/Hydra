"""Behavior gate + behavioral detector agree, and key on bulk encryption."""
import unittest

from common.config import FILES_K
from common.contracts import ArenaObservation
from detectors import falco_detector
from referee.gate import behavior_preserved


def _obs(encrypted, files=None, compiled=True):
    files = encrypted if files is None else files
    return ArenaObservation(compiled=compiled, files_written=files,
                            encrypted_files=encrypted, mean_entropy=8.0 if encrypted else 0.0)


class TestGate(unittest.TestCase):
    def test_bulk_encryption_fires_and_is_preserved(self):
        obs = _obs(FILES_K + 5)
        self.assertTrue(behavior_preserved(obs))
        self.assertEqual(falco_detector.evaluate(obs), "FIRED")

    def test_many_plaintext_files_do_not_fire(self):
        # writes lots of files but encrypts none — must stay SILENT (specificity)
        obs = _obs(encrypted=0, files=FILES_K + 20)
        self.assertFalse(behavior_preserved(obs))
        self.assertEqual(falco_detector.evaluate(obs), "SILENT")

    def test_a_few_encrypted_files_do_not_fire(self):
        obs = _obs(3)
        self.assertEqual(falco_detector.evaluate(obs), "SILENT")

    def test_non_compiling_is_silent(self):
        self.assertEqual(falco_detector.evaluate(_obs(50, compiled=False)), "SILENT")


if __name__ == "__main__":
    unittest.main()
