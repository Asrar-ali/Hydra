"""Trace parser: derives files, entropy, and network attempts from strace text.
Runs without Docker."""
import unittest

from arena.trace import parse


def _hex(s: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in s)


class TestTrace(unittest.TestCase):
    def test_counts_distinct_written_files_and_ignores_stdout(self):
        p1 = _hex(b"/tmp/hydra_work/a")
        p2 = _hex(b"/tmp/hydra_work/b")
        trace = "\n".join([
            f'openat(AT_FDCWD, "{p1}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 3',
            f'write(3, "{_hex(b"AAAA")}", 4) = 4',
            f'openat(AT_FDCWD, "{p2}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = 4',
            f'write(4, "{_hex(b"BBBB")}", 4) = 4',
            f'write(1, "{_hex(b"hello")}", 5) = 5',   # stdout, ignored
        ])
        r = parse(trace)
        self.assertEqual(r["files_written"], 2)
        self.assertEqual(r["network_attempts"], 0)
        self.assertTrue(all(p.startswith("/tmp/") for p in r["write_paths"]))

    def test_last_write_entropy_wins(self):
        path = _hex(b"/tmp/hydra_work/f")
        low = _hex(b"A" * 64)                       # entropy 0
        high = _hex(bytes(range(64)))               # high entropy, written last
        trace = "\n".join([
            f'openat(AT_FDCWD, "{path}", O_WRONLY|O_CREAT, 0666) = 3',
            f'write(3, "{low}", 64) = 64',
            f'openat(AT_FDCWD, "{path}", O_WRONLY|O_TRUNC, 0666) = 3',
            f'write(3, "{high}", 64) = 64',
        ])
        r = parse(trace)
        self.assertEqual(r["files_written"], 1)
        self.assertGreater(r["mean_entropy"], 5.0)   # reflects the last (high) write

    def test_detects_network_attempt(self):
        trace = "connect(5, {sa_family=AF_INET, sin_port=htons(80)}, 16) = -1 ENETUNREACH"
        self.assertEqual(parse(trace)["network_attempts"], 1)

    def test_strips_strace_f_pid_prefix(self):
        path = _hex(b"/tmp/hydra_work/a")
        trace = "\n".join([
            f'16    openat(AT_FDCWD, "{path}", O_WRONLY|O_CREAT, 0666) = 3',
            f'16    write(3, "{_hex(b"ABCD")}", 4) = 4',
        ])
        r = parse(trace)
        self.assertEqual(r["files_written"], 1)
        self.assertIn("write", r["syscalls"])


if __name__ == "__main__":
    unittest.main()
