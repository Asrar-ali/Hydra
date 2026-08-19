"""Trace parser: derives files, entropy, and network attempts from strace text.
Runs without Docker."""
import unittest

from arena.trace import parse
from common.config import RATE_WINDOW_SECONDS


def _hex(s: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in s)


_LOW = b"A" * 256                    # entropy 0.0
_HIGH = bytes(range(256))            # entropy 8.0


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

    def test_attributes_victims_per_pid_across_two_processes(self):
        """Two pids, each opening+writing plaintext then rewriting IN PLACE
        with high-entropy content to 3 distinct files: 6 victims total, but
        no single pid is attributed more than 3 — the per_process rule keys
        on max_encrypted_per_pid, not encrypted_outcome."""
        def victim_lines(pid: int, path: bytes, fd: int, t: str) -> list[str]:
            p = _hex(path)
            return [
                f'{pid}  {t} openat(AT_FDCWD, "{p}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = {fd}',
                f'{pid}  {t} write({fd}, "{_hex(_LOW)}", 256) = 256',
                f'{pid}  {t} write({fd}, "{_hex(_HIGH)}", 256) = 256',
            ]

        lines: list[str] = []
        pid_a_paths = [b"/tmp/hydra_work/a1", b"/tmp/hydra_work/a2", b"/tmp/hydra_work/a3"]
        pid_b_paths = [b"/tmp/hydra_work/b1", b"/tmp/hydra_work/b2", b"/tmp/hydra_work/b3"]
        for i, path in enumerate(pid_a_paths):
            lines += victim_lines(1111, path, 3 + i, f"10:00:0{i}.000000")
        for i, path in enumerate(pid_b_paths):
            lines += victim_lines(2222, path, 13 + i, f"10:00:1{i}.000000")

        trace = "\n".join(lines)
        r = parse(trace)
        self.assertEqual(r["files_written"], 6)
        self.assertEqual(r["encrypted_outcome"], 6)
        self.assertEqual(r["max_encrypted_per_pid"], 3)   # not 6: fan-out across pids
        self.assertEqual(
            sorted(r["write_paths"]),
            sorted(p.decode() for p in pid_a_paths + pid_b_paths),
        )

    def test_max_rate_in_window_uses_a_sliding_window(self):
        """8 victims: 4 clustered at t=0.0..0.3s, 4 more clustered at
        t=5.0..5.3s. Both clusters fit inside a 2.0s window on their own, but
        the two clusters together never do — the sliding-window max must be
        4, not 8."""
        self.assertEqual(RATE_WINDOW_SECONDS, 2.0)

        def victim_lines(path: bytes, fd: int, t: str) -> list[str]:
            p = _hex(path)
            return [
                f'9999  {t} openat(AT_FDCWD, "{p}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = {fd}',
                f'9999  {t} write({fd}, "{_hex(_HIGH)}", 256) = 256',
            ]

        times = [
            "00:00:00.000000", "00:00:00.100000", "00:00:00.200000", "00:00:00.300000",
            "00:00:05.000000", "00:00:05.100000", "00:00:05.200000", "00:00:05.300000",
        ]
        lines: list[str] = []
        for i, t in enumerate(times):
            lines += victim_lines(f"/tmp/hydra_work/r{i}".encode(), 3 + i, t)

        trace = "\n".join(lines)
        r = parse(trace)
        self.assertEqual(r["encrypted_outcome"], 8)
        self.assertEqual(r["max_rate_in_window"], 4)   # never 8: the two clusters are 5s apart

    def test_reassembles_split_syscalls_and_isolates_fds_per_pid(self):
        """The fan-out failure mode: under strace -f, concurrent children (a)
        reuse the same low fd numbers and (b) get their syscalls split across
        "<unfinished ...>" / "<... resumed>" lines. Two pids each open fd 3 to a
        DIFFERENT path (split openat), then rewrite it in place with high entropy
        (one split write). A global fd map would collapse both to one path; not
        reassembling the split lines would drop the opens entirely. Correct
        parsing yields 2 victims, one per pid."""
        pa = _hex(b"/tmp/hydra_work/c0")
        pb = _hex(b"/tmp/hydra_work/c1")
        hi = _hex(_HIGH)
        lo = _hex(_LOW)
        trace = "\n".join([
            # both children open fd 3 to different paths, interleaved + split
            f'17  10:00:00.000000 openat(AT_FDCWD, "{pa}", O_WRONLY|O_CREAT|O_TRUNC, 0666 <unfinished ...>',
            f'18  10:00:00.000001 openat(AT_FDCWD, "{pb}", O_WRONLY|O_CREAT|O_TRUNC, 0666 <unfinished ...>',
            f'17  10:00:00.000002 <... openat resumed>) = 3',
            f'18  10:00:00.000003 <... openat resumed>) = 3',
            # plaintext write to each (same fd number, different pid)
            f'17  10:00:00.000004 write(3, "{lo}", 256) = 256',
            f'18  10:00:00.000005 write(3, "{lo}", 256) = 256',
            # high-entropy rewrite in place — one of them split across lines
            f'17  10:00:00.000006 write(3, "{hi}", 256 <unfinished ...>',
            f'18  10:00:00.000007 write(3, "{hi}", 256) = 256',
            f'17  10:00:00.000008 <... write resumed>) = 256',
        ])
        r = parse(trace)
        self.assertEqual(r["files_written"], 2)          # not 1 (fds isolated per pid)
        self.assertEqual(r["encrypted_outcome"], 2)      # both victims captured
        self.assertEqual(r["encrypted_in_place"], 2)     # each overwritten in place
        self.assertEqual(r["max_encrypted_per_pid"], 1)  # one victim per pid

    def test_degrades_gracefully_without_pid_or_timestamp(self):
        """A trace with neither pid nor -tt prefixes (like the pre-Phase-1
        traces above) still parses, and both new facts collapse to
        encrypted_outcome: one implicit pid, one implicit window."""
        paths = [b"/tmp/hydra_work/x", b"/tmp/hydra_work/y", b"/tmp/hydra_work/z"]
        lines: list[str] = []
        for i, path in enumerate(paths):
            p = _hex(path)
            fd = 3 + i
            lines.append(f'openat(AT_FDCWD, "{p}", O_WRONLY|O_CREAT|O_TRUNC, 0666) = {fd}')
            lines.append(f'write({fd}, "{_hex(_HIGH)}", 256) = 256')

        trace = "\n".join(lines)
        r = parse(trace)
        self.assertEqual(r["encrypted_outcome"], 3)
        self.assertEqual(r["max_rate_in_window"], r["encrypted_outcome"])
        self.assertEqual(r["max_encrypted_per_pid"], r["encrypted_outcome"])


if __name__ == "__main__":
    unittest.main()
