"""Mechanism toolbox stub (Phase 0). No model or container needed.

Freezes the interface the detection-rule robustness scorer will drive:
MECHANISMS, apply_mechanism, mechanism_prompt. Only write_inplace and
rename_swap are real today; the rest are Phase 1 stubs. See
ARCHITECTURE.md §9.2 and adversary/mechanisms.py.
"""
import unittest

from adversary import mechanisms


class TestMechanismsList(unittest.TestCase):
    def test_non_empty(self):
        self.assertTrue(mechanisms.MECHANISMS)

    def test_all_entries_are_str(self):
        for name in mechanisms.MECHANISMS:
            self.assertIsInstance(name, str)


class TestApplyMechanism(unittest.TestCase):
    def test_write_inplace_is_the_seed(self):
        out = mechanisms.apply_mechanism("write_inplace")
        self.assertIn("mkdtemp", out)

    def test_rename_swap_is_the_rename_seed(self):
        out = mechanisms.apply_mechanism("rename_swap")
        self.assertIn("rename", out)

    def test_every_mechanism_returns_compilable_looking_c(self):
        for name in mechanisms.MECHANISMS:
            out = mechanisms.apply_mechanism(name)
            self.assertTrue(out, f"{name} returned empty source")
            self.assertIn("int main", out)

    def test_stub_mechanisms_are_clearly_marked(self):
        for name in ("throttle", "fanout", "mmap"):
            out = mechanisms.apply_mechanism(name)
            self.assertIn("MECHANISM STUB", out)

    def test_unknown_mechanism_raises(self):
        with self.assertRaises(ValueError):
            mechanisms.apply_mechanism("bogus")


class TestMechanismPrompt(unittest.TestCase):
    def test_mentions_fired_rule_and_preservation(self):
        prompt = mechanisms.mechanism_prompt("naive_inplace", "int main(){}")
        self.assertIsInstance(prompt, str)
        self.assertIn("naive_inplace", prompt)
        lowered = prompt.lower()
        self.assertTrue("preserve" in lowered or "behavior" in lowered)


if __name__ == "__main__":
    unittest.main()
