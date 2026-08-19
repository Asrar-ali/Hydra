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

import os
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


class TestScorerLLMOverlay(unittest.TestCase):
    """Phase 2: the opt-in LLM overlay (HYDRA_SCORE_LLM=1). Mocks the same
    two arena-touching seams as above, plus the adversary itself
    (adversary.llm.rewrite/extract_c, as imported into referee.scorer) and
    the overlay's own reachability check (_use_llm) — still no Ollama, no
    Docker. Reuses the Phase-1 toolbox matrix (_OBS_BY_MECH) above, so
    naive_inplace/rate_windowed/per_process are the toolbox-evaded rules the
    overlay gets a shot at."""

    LLM_CANDIDATE = "LLM_CANDIDATE_SOURCE_NAIVE_INPLACE"

    def setUp(self):
        patchers = [
            patch("referee.scorer.apply_mechanism", side_effect=_fake_apply_mechanism),
            patch("referee.scorer.run_detailed", side_effect=self._fake_run_detailed),
            patch("referee.scorer._use_llm", return_value=True),
            patch("referee.scorer.llm.rewrite", side_effect=self._fake_llm_rewrite),
            patch("referee.scorer.llm.extract_c", side_effect=lambda text: text),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)
        os.environ["HYDRA_SCORE_LLM"] = "1"
        self.addCleanup(os.environ.pop, "HYDRA_SCORE_LLM", None)

    def _fake_llm_rewrite(self, feedback, timeout=None, **kwargs):
        # Only "discovers" an independent evasion for naive_inplace (its
        # fired-rule name is embedded in feedback.reason via
        # mechanism_prompt). Every other rule's attempt raises, exercising
        # the swallow-and-keep-the-offline-result path in the same run.
        if "naive_inplace" in feedback.reason:
            return self.LLM_CANDIDATE
        raise RuntimeError("simulated ollama failure")

    def _fake_run_detailed(self, source, **kwargs):
        if source == self.LLM_CANDIDATE:
            # Evades naive_inplace (no in-place rewrites) while every other
            # signal, including the ones the gate checks, stays >= N — so
            # behavior_preserved() is True.
            return _obs(encrypted_in_place=0), {}
        return _OBS_BY_MECH[source], {}

    def _rules(self) -> dict[str, dict]:
        from referee.scorer import run_scorecard

        card = run_scorecard(12)
        return {r["rule"]: r for r in card["rules"]}

    def test_llm_independently_evades_naive_inplace(self):
        r = self._rules()["naive_inplace"]
        self.assertTrue(r["llm_evaded"])
        self.assertEqual(r["provenance"], "llm")
        self.assertTrue(r["llm_note"])
        # the deterministic toolbox metric is untouched by the overlay
        self.assertTrue(r["evaded"])
        self.assertEqual(r["evasion_depth"], 2)
        self.assertEqual(r["mechanism_that_evaded"], "rename_swap")

    def test_llm_failure_is_swallowed_and_offline_result_stands(self):
        r = self._rules()["rate_windowed"]
        # llm.rewrite raised for this rule -> overlay attempt swallowed, no
        # crash, and the offline toolbox result stands unaffected.
        self.assertFalse(r["llm_evaded"])
        self.assertIsNone(r["llm_note"])
        self.assertEqual(r["provenance"], "offline")
        self.assertTrue(r["evaded"])
        self.assertEqual(r["evasion_depth"], 3)
        self.assertEqual(r["mechanism_that_evaded"], "throttle")

    def test_never_evaded_rules_skip_the_llm_overlay(self):
        # write_content/robust_outcome are never evaded by the toolbox, so
        # the (expensive) overlay attempt must not even run for them.
        rules = self._rules()
        for name in ("write_content", "robust_outcome"):
            self.assertFalse(rules[name]["llm_evaded"])
            self.assertIsNone(rules[name]["llm_note"])
            self.assertEqual(rules[name]["provenance"], "offline")


class TestScorerLLMOverlayOffByDefault(unittest.TestCase):
    """The overlay must stay off whenever HYDRA_SCORE_LLM is unset, even if
    the adversary would otherwise be reachable — default (offline) runs,
    including every other test in this module, must be unaffected."""

    def setUp(self):
        os.environ.pop("HYDRA_SCORE_LLM", None)
        patchers = [
            patch("referee.scorer.apply_mechanism", side_effect=_fake_apply_mechanism),
            patch("referee.scorer.run_detailed", side_effect=_fake_run_detailed),
            patch("referee.scorer.llm.is_available", return_value=True),
        ]
        for p in patchers:
            p.start()
            self.addCleanup(p.stop)

    def test_overlay_off_by_default(self):
        from referee.scorer import run_scorecard

        card = run_scorecard(12)
        for r in card["rules"]:
            self.assertFalse(r["llm_evaded"])
            self.assertIsNone(r["llm_note"])
            self.assertEqual(r["provenance"], "offline")


if __name__ == "__main__":
    unittest.main()
