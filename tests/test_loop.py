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


if __name__ == "__main__":
    unittest.main()
