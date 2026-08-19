"""Robustness-scorer search (Phase 1). No Docker needed.

Mocks the two arena-touching seams referee.scorer imports — ``run_detailed``
(one arena run per mechanism) and ``apply_mechanism`` (mechanism name ->
source) — so the real search logic in ``score_rules_events`` runs against
hand-built ArenaObservations instead of a real container.

The mocked matrix encodes the expected Phase-1 leaderboard (ARCHITECTURE.md
§9.2, §11): write_inplace fires every rule; rename_swap zeroes
``encrypted_in_place`` only (evades naive_inplace, depth 2); throttle zeroes
``max_rate_in_window`` only (evades rate_windowed, depth 3); fanout zeroes
``max_encrypted_per_pid`` only (evades per_process, depth 4); mmap is still a
Phase-0/1 stub identical to write_inplace (evades nothing). ``encrypted_files``
and ``encrypted_outcome`` stay at N (>= FILES_K) everywhere, so write_content
and robust_outcome are never evaded and behavior is preserved throughout.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from common.config import FILES_K
from common.contracts import ArenaObservation

N = FILES_K + 5  # comfortably above the bulk-encryption threshold


def _obs(**overrides) -> ArenaObservation:
    base = dict(
        compiled=True,
        encrypted_files=N,
        encrypted_in_place=N,
        encrypted_outcome=N,
        max_encrypted_per_pid=N,
        max_rate_in_window=N,
    )
    base.update(overrides)
    return ArenaObservation(**base)


# Mechanism name -> its ArenaObservation. Keyed by mechanism NAME (not index)
# because the fake apply_mechanism below returns the name as the "source",
# and the fake run_detailed looks it up by that source.
_OBS_BY_MECH: dict[str, ArenaObservation] = {
    "write_inplace": _obs(),
    "rename_swap": _obs(encrypted_in_place=0),
    "throttle": _obs(max_rate_in_window=0),
    "fanout": _obs(max_encrypted_per_pid=0),
    "mmap": _obs(),  # stub in Phase 1 — same as write_inplace, evades nothing
}


def _fake_apply_mechanism(name: str) -> str:
    """Stand in for adversary.mechanisms.apply_mechanism: return the
    mechanism name itself as the "source" so the fake run_detailed below can
    map it straight back to the right canned observation."""
    return name


def _fake_run_detailed(source: str, **kwargs):
    """Stand in for arena.run.run_detailed: no container, just look up the
    canned observation for this "source" (== mechanism name, per
    _fake_apply_mechanism above)."""
    return _OBS_BY_MECH[source], {}


class TestScorerSearch(unittest.TestCase):
    def setUp(self):
        patchers = [
            patch("referee.scorer.run_detailed", side_effect=_fake_run_detailed),
            patch("referee.scorer.apply_mechanism", side_effect=_fake_apply_mechanism),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def _rules(self) -> dict[str, dict]:
        from referee.scorer import run_scorecard

        card = run_scorecard(12)
        return {r["rule"]: r for r in card["rules"]}

    def test_naive_inplace_evaded_by_rename_swap_at_depth_2(self):
        r = self._rules()["naive_inplace"]
        self.assertTrue(r["evaded"])
        self.assertEqual(r["evasion_depth"], 2)
        self.assertEqual(r["mechanism_that_evaded"], "rename_swap")

    def test_rate_windowed_evaded_by_throttle_at_depth_3(self):
        r = self._rules()["rate_windowed"]
        self.assertTrue(r["evaded"])
        self.assertEqual(r["evasion_depth"], 3)
        self.assertEqual(r["mechanism_that_evaded"], "throttle")

    def test_per_process_evaded_by_fanout_at_depth_4(self):
        r = self._rules()["per_process"]
        self.assertTrue(r["evaded"])
        self.assertEqual(r["evasion_depth"], 4)
        self.assertEqual(r["mechanism_that_evaded"], "fanout")

    def test_write_content_never_evaded(self):
        r = self._rules()["write_content"]
        self.assertFalse(r["evaded"])
        self.assertIsNone(r["evasion_depth"])
        self.assertIsNone(r["mechanism_that_evaded"])

    def test_robust_outcome_never_evaded(self):
        r = self._rules()["robust_outcome"]
        self.assertFalse(r["evaded"])
        self.assertIsNone(r["evasion_depth"])
        self.assertIsNone(r["mechanism_that_evaded"])


class TestRunScorecardStructure(unittest.TestCase):
    def setUp(self):
        patchers = [
            patch("referee.scorer.run_detailed", side_effect=_fake_run_detailed),
            patch("referee.scorer.apply_mechanism", side_effect=_fake_apply_mechanism),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_scorecard_shape(self):
        from referee.scorer import run_scorecard

        card = run_scorecard(12)
        self.assertIn("mode", card)
        self.assertIn("total_iterations", card)
        self.assertIn("rules", card)
        self.assertEqual(len(card["rules"]), 5)


if __name__ == "__main__":
    unittest.main()
