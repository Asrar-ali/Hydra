"""Mechanism toolbox tests (Phase 1). No model or container needed.

Exercises the interface the detection-rule robustness scorer drives:
MECHANISMS, apply_mechanism, mechanism_prompt. write_inplace, rename_swap,
throttle, and fanout are all real now; only mmap remains a stub. See
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

    def test_throttle_is_the_throttle_seed(self):
        out = mechanisms.apply_mechanism("throttle")
        self.assertIn("sleep", out)
        self.assertIn("int main", out)

    def test_fanout_is_the_fanout_seed(self):
        out = mechanisms.apply_mechanism("fanout")
        self.assertIn("fork", out)
        self.assertIn("int main", out)

    def test_every_mechanism_returns_compilable_looking_c(self):
        for name in mechanisms.MECHANISMS:
            out = mechanisms.apply_mechanism(name)
            self.assertTrue(out, f"{name} returned empty source")
            self.assertIn("int main", out)

    def test_stub_mechanisms_are_clearly_marked(self):
        for name in ("mmap",):
            out = mechanisms.apply_mechanism(name)
            self.assertIn("MECHANISM STUB", out)

    def test_implemented_mechanisms_are_not_marked_as_stubs(self):
        for name in ("write_inplace", "rename_swap", "throttle", "fanout"):
            out = mechanisms.apply_mechanism(name)
            self.assertNotIn("MECHANISM STUB", out)

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
