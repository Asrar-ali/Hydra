"""LLM reply -> source extraction (C for metamorphic mode, Python for
promptlock mode). No model needed."""
import unittest

from adversary.llm import _extract_c, extract_py

PROGRAM = '#include <stdio.h>\nint main(void){return 0;}'
PYPROGRAM = 'import os\ndef main():\n    pass'


class TestExtract(unittest.TestCase):
    def test_fenced_c_block(self):
        self.assertEqual(_extract_c(f"Sure!\n```c\n{PROGRAM}\n```\nDone."), PROGRAM)

    def test_fenced_without_lang(self):
        self.assertEqual(_extract_c(f"```\n{PROGRAM}\n```"), PROGRAM)

    def test_plain_with_prose_prefix(self):
        self.assertEqual(_extract_c(f"Here is the code:\n{PROGRAM}"), PROGRAM)

    def test_picks_largest_block(self):
        text = f"```\nshort\n```\nand\n```c\n{PROGRAM}\n```"
        self.assertEqual(_extract_c(text), PROGRAM)


class TestExtractPy(unittest.TestCase):
    def test_fenced_python_block(self):
        self.assertEqual(extract_py(f"Sure!\n```python\n{PYPROGRAM}\n```\nDone."), PYPROGRAM)

    def test_fenced_without_lang(self):
        self.assertEqual(extract_py(f"```\n{PYPROGRAM}\n```"), PYPROGRAM)

    def test_plain_with_prose_prefix(self):
        self.assertEqual(extract_py(f"Here is the script:\n{PYPROGRAM}"), PYPROGRAM)

    def test_picks_largest_block(self):
        text = f"```\nshort\n```\nand\n```py\n{PYPROGRAM}\n```"
        self.assertEqual(extract_py(text), PYPROGRAM)


if __name__ == "__main__":
    unittest.main()
