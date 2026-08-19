"""Rules registry: exactly 5 named rules, each keyed on one derived fact.

The key contrast this proves: a rule keyed on a mechanism-specific fact
(``encrypted_in_place``) stays SILENT on a rename-swap outcome, while the
rule keyed on the outcome (``encrypted_outcome``) still fires. See
ARCHITECTURE.md §9.2 and detectors/rules_registry.py.
"""
import unittest

from common.config import FILES_K
from common.contracts import ArenaObservation
from detectors.rules_registry import RULES, RuleSpec, evaluate_all

EXPECTED_NAMES = [
    "naive_inplace",
    "write_content",
    "rate_windowed",
    "per_process",
    "robust_outcome",
]


def _obs_with_extra(compiled: bool, **kwargs) -> ArenaObservation:
    """Build an ArenaObservation, tolerating max_rate_in_window /
    max_encrypted_per_pid not existing yet as declared fields (a parallel
    lane may still be adding them) by falling back to setattr."""
    known_fields = {"encrypted_in_place", "encrypted_files", "encrypted_outcome"}
    ctor_kwargs = {"compiled": compiled}
    extra = {}
    for k, v in kwargs.items():
        if k in known_fields or k in ("files_written", "mean_entropy"):
            ctor_kwargs[k] = v
        else:
            extra[k] = v
    try:
        obs = ArenaObservation(**ctor_kwargs, **extra)
    except TypeError:
        obs = ArenaObservation(**ctor_kwargs)
        for k, v in extra.items():
            setattr(obs, k, v)
    return obs


class TestRulesRegistry(unittest.TestCase):
    def test_registry_has_exactly_five_named_rules(self):
        self.assertEqual(list(RULES.keys()), EXPECTED_NAMES)
        for name, spec in RULES.items():
            self.assertIsInstance(spec, RuleSpec)
            self.assertEqual(spec.name, name)
            self.assertTrue(callable(spec.evaluate))

    def test_all_rules_fire_when_every_keyed_fact_is_above_threshold(self):
        n = FILES_K + 2
        obs = _obs_with_extra(
            True,
            encrypted_in_place=n,
            encrypted_files=n,
            encrypted_outcome=n,
            max_rate_in_window=n,
            max_encrypted_per_pid=n,
        )
        verdicts = evaluate_all(obs)
        self.assertEqual(set(verdicts.keys()), set(EXPECTED_NAMES))
        for name in EXPECTED_NAMES:
            self.assertEqual(verdicts[name], "FIRED", f"{name} should be FIRED")

    def test_all_rules_silent_when_not_compiled(self):
        n = FILES_K + 2
        obs = _obs_with_extra(
            False,
            encrypted_in_place=n,
            encrypted_files=n,
            encrypted_outcome=n,
            max_rate_in_window=n,
            max_encrypted_per_pid=n,
        )
        verdicts = evaluate_all(obs)
        for name in EXPECTED_NAMES:
            self.assertEqual(verdicts[name], "SILENT", f"{name} should be SILENT")

    def test_rename_swap_outcome_evades_naive_but_not_robust(self):
        # Rename-swap: victims end high-entropy (outcome), but none were ever
        # overwritten IN PLACE, and no per-mechanism signal fired either.
        n = FILES_K + 2
        obs = _obs_with_extra(
            True,
            encrypted_in_place=0,
            encrypted_files=0,
            encrypted_outcome=n,
            max_rate_in_window=0,
            max_encrypted_per_pid=0,
        )
        verdicts = evaluate_all(obs)
        self.assertEqual(verdicts["naive_inplace"], "SILENT")
        self.assertEqual(verdicts["robust_outcome"], "FIRED")


if __name__ == "__main__":
    unittest.main()
