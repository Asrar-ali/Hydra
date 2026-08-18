"""Promptlock mode (ARCHITECTURE.md §9.3) — runtime-generated payload.

Offline checks (fallback generator produces valid, varying Python) run always.
Real-sandbox checks require Docker + the arena image (rebuilt with python3 and
the script entrypoint); skipped otherwise.
"""
import py_compile
import shutil
import subprocess
import tempfile
import unittest

from adversary.mutator import generate_promptlock
from referee.gate import behavior_preserved
from referee.loop import run_loop


def _image_present() -> bool:
    if shutil.which("docker") is None:
        return False
    r = subprocess.run(["docker", "image", "inspect", "hydra-arena"], capture_output=True)
    return r.returncode == 0


class TestPromptlockFallback(unittest.TestCase):
    """The deterministic no-LLM stand-in: valid Python, varies per iteration."""

    def test_generates_compilable_python(self):
        for i in (1, 2, 7):
            src = generate_promptlock(i)
            with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as tf:
                tf.write(src)
                path = tf.name
            py_compile.compile(path, doraise=True)  # raises on syntax error

    def test_varies_by_iteration(self):
        variants = {generate_promptlock(i) for i in range(5)}
        self.assertEqual(len(variants), 5)


class TestPromptlockFakeLoop(unittest.TestCase):
    """The referee's promptlock path (fake arena, no Docker/LLM needed)."""

    def test_run_loop_promptlock_shape(self):
        result = run_loop(3, mode="promptlock")
        s = result["summary"]
        self.assertEqual(s["mode"], "promptlock")
        self.assertEqual(s["total_iterations"], 4)  # baseline + 3 generated runs
        self.assertIn("signature_evasions_by_regeneration", s)
        self.assertIn("behavioral_evasions_while_behavior_preserved", s)
        self.assertEqual(len(result["iterations"]), 4)


@unittest.skipUnless(_image_present(), "docker + hydra-arena image required")
class TestPromptlockSandbox(unittest.TestCase):
    """Real-sandbox safety: the runtime-generated-script path obeys the same
    invariants as compiled-C candidates (ARCHITECTURE.md §6)."""

    def test_seed_script_runs_clean_and_confined(self):
        from arena.run import run_detailed

        with open("sample/seed_promptlock.py", encoding="utf-8") as fh:
            source = fh.read()
        obs, report = run_detailed(source, mode="promptlock")
        self.assertTrue(obs.compiled, obs.error)
        self.assertEqual(obs.exit_code, 0)
        self.assertIsNone(obs.error)
        self.assertTrue(behavior_preserved(obs))
        self.assertEqual(report["network_attempts"], 0)
        outside = [p for p in report["write_paths"] if not p.startswith("/tmp/")]
        self.assertEqual(outside, [], f"writes escaped the sandbox: {outside}")

    def test_offline_fallback_runs_clean_and_confined(self):
        from arena.run import run_detailed

        obs, report = run_detailed(generate_promptlock(9), mode="promptlock")
        self.assertTrue(obs.compiled, obs.error)
        self.assertEqual(obs.exit_code, 0)
        self.assertTrue(behavior_preserved(obs))
        self.assertEqual(report["network_attempts"], 0)
        outside = [p for p in report["write_paths"] if not p.startswith("/tmp/")]
        self.assertEqual(outside, [], f"writes escaped the sandbox: {outside}")


if __name__ == "__main__":
    unittest.main()
