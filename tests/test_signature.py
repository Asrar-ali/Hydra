"""Signature is seeded from the seed and evaded by the mutator."""
import unittest

from adversary import mutator
from detectors import yara_detector


class TestSignature(unittest.TestCase):
    def setUp(self):
        with open("sample/seed.c", encoding="utf-8") as fh:
            self.seed = fh.read()
        self.rule = yara_detector.build_rule(self.seed.encode())

    def test_seed_matches_its_own_signature(self):
        self.assertEqual(yara_detector.scan(self.seed.encode(), self.rule), "MATCH")

    def test_mutation_evades_signature(self):
        mutated = mutator.mutate(self.seed, 1)
        self.assertEqual(yara_detector.scan(mutated.encode(), self.rule), "CLEAN")


if __name__ == "__main__":
    unittest.main()
