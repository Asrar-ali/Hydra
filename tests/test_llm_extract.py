"""LLM reply -> C source extraction. No model needed."""
import unittest

from adversary.llm import _extract_c

PROGRAM = '#include <stdio.h>\nint main(void){return 0;}'


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


if __name__ == "__main__":
    unittest.main()
