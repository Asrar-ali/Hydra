"""Offline mutator (Track-1 fallback). No model or container needed.

The mutator can't *adapt* (that's the LLM's job) but it must produce
byte-different, behavior-identical variants, and a genuinely de-fanged program
for the finale. See ARCHITECTURE.md §5, §5.2.
"""
import unittest

from adversary import mutator
from arena.run import BEHAVIOR_DISABLED_MARK


class TestMutate(unittest.TestCase):
    def setUp(self):
        with open("sample/seed.c", encoding="utf-8") as fh:
            self.seed = fh.read()

    def test_changes_bytes(self):
        self.assertNotEqual(mutator.mutate(self.seed, 1), self.seed)

    def test_rewrites_the_signature_marker(self):
        # The build-specific strings the family signature keys on must change:
        # the marker, temp-dir name, status message and filename format are all
        # rewritten to defeat the multi-indicator rule.
        out = mutator.mutate(self.seed, 1)
        self.assertNotIn("HYDRA-SIGNATURE-000", out)
        self.assertNotIn("hydra_work", out)
        self.assertNotIn("file_%02d.dat", out)

    def test_preserves_behavior_critical_pieces(self):
        # Byte features change, but the /tmp sandbox and the %02d format specifier
        # (behavior) must survive, or the sample would break or escape.
        out = mutator.mutate(self.seed, 7)
        self.assertIn("/tmp/", out)
        self.assertIn("%02d", out)

    def test_deterministic_for_same_iteration(self):
        self.assertEqual(mutator.mutate(self.seed, 3), mutator.mutate(self.seed, 3))

    def test_different_iterations_differ(self):
        self.assertNotEqual(mutator.mutate(self.seed, 1), mutator.mutate(self.seed, 2))

    def test_provenance_is_offline(self):
        self.assertEqual(mutator.provenance, "offline")


class TestDisableBehavior(unittest.TestCase):
    def test_defanged_program_carries_the_disabled_mark(self):
        out = mutator.disable_behavior("anything")
        self.assertIn(BEHAVIOR_DISABLED_MARK, out)

    def test_defanged_program_has_no_file_rewrite_loop(self):
        # The whole point of the finale: it stops doing the behavior.
        out = mutator.disable_behavior("anything")
        self.assertNotIn("fopen", out)
        self.assertNotIn("fwrite", out)
        self.assertIn("int main", out)


if __name__ == "__main__":
    unittest.main()
