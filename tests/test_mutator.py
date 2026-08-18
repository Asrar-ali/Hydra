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
        # The build-specific marker the signature keys on must change.
        out = mutator.mutate(self.seed, 1)
        self.assertNotIn("HYDRA-SIGNATURE-000", out)
        self.assertIn("HYDRA-SIGNATURE-", out)  # still a marker, just a different one

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
