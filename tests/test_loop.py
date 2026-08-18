"""Integration: a full referee loop in fake mode produces the expected summary.

Validates ARCHITECTURE.md §10 success criteria without Docker or Ollama.
"""
import os
import unittest


class TestLoop(unittest.TestCase):
    def setUp(self):
        os.environ["HYDRA_FAKE"] = "1"

    def tearDown(self):
        os.environ.pop("HYDRA_FAKE", None)

    def test_full_loop_summary(self):
        from referee.loop import run_loop

        result = run_loop(cap=2)
        s = result["summary"]

        # §10 success criteria
        self.assertTrue(s["signature_evaded"])
        self.assertEqual(s["iterations_to_evade_signature"], 1)
        self.assertEqual(s["behavioral_evasions_while_behavior_preserved"], 0)
        self.assertTrue(s["behavioral_evasion_required_breaking_behavior"])

        # baseline + 1 track-1 + 2 track-2 + 1 finale
        self.assertEqual(s["total_iterations"], 5)
        self.assertEqual(len(result["iterations"]), 5)

    def test_loop_event_sequence(self):
        from referee.loop import run_events

        events = list(run_events(cap=2))
        names = [e[0] for e in events]

        self.assertEqual(names[0], "baseline")
        self.assertIn("verdict", names)
        self.assertEqual(names[-1], "summary")
        # no error event in a successful fake run
        self.assertNotIn("error", names)


class TestSSEContract(unittest.TestCase):
    """SSE event contract smoke test — ARCHITECTURE.md §10, §11.

    Validates that run_events() in fake mode produces the correct event types,
    payload shapes, and ordering so the dashboard code path works identically
    for a live run and a replay.
    """

    def setUp(self):
        os.environ["HYDRA_FAKE"] = "1"

    def tearDown(self):
        os.environ.pop("HYDRA_FAKE", None)

    def _events(self):
        from referee.loop import run_events
        return list(run_events(cap=2))

    def test_envelope_ordering(self):
        events = self._events()
        names = [e[0] for e in events]
        self.assertEqual(names[0], "baseline", "first event must be baseline")
        self.assertEqual(names[-1], "summary", "last event must be summary")
        self.assertNotIn("error", names, "no error in a clean fake run")
        # every rewrite_done is immediately followed by its verdict
        for i, name in enumerate(names):
            if name == "rewrite_done":
                self.assertEqual(names[i + 1], "verdict",
                                 f"rewrite_done at index {i} not followed by verdict")

    def test_baseline_payload(self):
        name, data = self._events()[0]
        self.assertEqual(name, "baseline")
        for field in ("sha256", "yara", "falco", "source"):
            self.assertIn(field, data, f"baseline missing '{field}'")
        self.assertEqual(data["yara"], "MATCH")
        self.assertEqual(data["falco"], "FIRED")
        self.assertIsInstance(data["source"], str)
        self.assertTrue(data["source"])

    def test_rewrite_done_payload(self):
        events = self._events()
        done_events = [(n, d) for n, d in events if n == "rewrite_done"]
        self.assertTrue(done_events, "expected at least one rewrite_done")
        for _, data in done_events:
            for field in ("iteration", "track", "target", "provenance", "source", "sha256"):
                self.assertIn(field, data, f"rewrite_done missing '{field}'")
            self.assertIn(data["provenance"], ("llm", "offline"))
            self.assertIn(data["target"], ("yara", "falco"))

    def test_verdict_payload(self):
        events = self._events()
        verdicts = [(n, d) for n, d in events if n == "verdict"]
        self.assertTrue(verdicts)
        for _, data in verdicts:
            for field in ("iteration", "track", "target_detector", "source_sha256",
                          "compiled", "behavior_preserved", "files_written",
                          "mean_entropy", "yara", "falco", "provenance"):
                self.assertIn(field, data, f"verdict missing '{field}'")
            self.assertIn(data["yara"], ("MATCH", "CLEAN"))
            self.assertIn(data["falco"], ("FIRED", "SILENT"))

    def test_summary_payload(self):
        _, data = self._events()[-1]
        for field in ("iterations_to_evade_signature", "signature_evaded",
                      "total_iterations", "behavioral_evasions_while_behavior_preserved",
                      "behavioral_evasion_required_breaking_behavior"):
            self.assertIn(field, data, f"summary missing '{field}'")


if __name__ == "__main__":
    unittest.main()
