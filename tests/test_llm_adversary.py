"""LLM adversary — streaming, availability, and one-shot rewrite, with the
Ollama HTTP call mocked so these run fully offline (no model, no network).

Complements test_llm_extract.py (which covers extract_c on its own). Here we
exercise the pieces that talk to Ollama: is_available(), rewrite_stream(), and
rewrite(). See ARCHITECTURE.md §5.2.
"""
import io
import json
import unittest
from unittest import mock

from adversary import llm
from common.contracts import Feedback

PROGRAM = "#include <stdio.h>\nint main(void){return 0;}"


def _fake_http(body: bytes):
    """A context-manager stand-in for urllib.request.urlopen: iterating it and
    .read() both yield `body` (bytes). Mirrors how llm.py consumes the response."""
    resp = mock.MagicMock()
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = False
    resp.read.return_value = body
    resp.__iter__.return_value = iter(body.splitlines(keepends=True))
    return resp


def _stream_ndjson(tokens, done_extra=True):
    """Build an Ollama /api/chat streaming body: one JSON object per line."""
    lines = [json.dumps({"message": {"content": t}, "done": False}) for t in tokens]
    lines.append(json.dumps({"message": {"content": ""}, "done": True}))
    return ("\n".join(lines) + "\n").encode()


class TestIsAvailable(unittest.TestCase):
    def test_true_when_model_present(self):
        body = json.dumps({"models": [{"name": llm.ADVERSARY_MODEL}]}).encode()
        with mock.patch("urllib.request.urlopen", return_value=_fake_http(body)):
            self.assertTrue(llm.is_available())

    def test_true_when_model_has_tag_suffix(self):
        body = json.dumps({"models": [{"name": llm.ADVERSARY_MODEL + ":latest"}]}).encode()
        with mock.patch("urllib.request.urlopen", return_value=_fake_http(body)):
            self.assertTrue(llm.is_available())

    def test_false_when_model_absent(self):
        body = json.dumps({"models": [{"name": "some-other-model:latest"}]}).encode()
        with mock.patch("urllib.request.urlopen", return_value=_fake_http(body)):
            self.assertFalse(llm.is_available())

    def test_false_when_ollama_unreachable(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            self.assertFalse(llm.is_available())


class TestRewriteStream(unittest.TestCase):
    def setUp(self):
        self.fb = Feedback("yara", "matched a marker; change it", PROGRAM)

    def test_yields_content_tokens_in_order(self):
        body = _stream_ndjson(["#include ", "<stdio.h>\n", "int main(){}"])
        with mock.patch("urllib.request.urlopen", return_value=_fake_http(body)):
            toks = list(llm.rewrite_stream(self.fb))
        self.assertEqual(toks, ["#include ", "<stdio.h>\n", "int main(){}"])

    def test_stops_at_done(self):
        # A token AFTER the done marker must not be yielded.
        lines = [
            json.dumps({"message": {"content": "keep"}, "done": False}),
            json.dumps({"message": {"content": ""}, "done": True}),
            json.dumps({"message": {"content": "DROP"}, "done": False}),
        ]
        body = ("\n".join(lines) + "\n").encode()
        with mock.patch("urllib.request.urlopen", return_value=_fake_http(body)):
            toks = list(llm.rewrite_stream(self.fb))
        self.assertEqual(toks, ["keep"])

    def test_skips_blank_and_malformed_lines(self):
        lines = [
            "",
            "not json",
            json.dumps({"message": {"content": "ok"}, "done": False}),
            json.dumps({"message": {"content": ""}, "done": True}),
        ]
        body = ("\n".join(lines) + "\n").encode()
        with mock.patch("urllib.request.urlopen", return_value=_fake_http(body)):
            toks = list(llm.rewrite_stream(self.fb))
        self.assertEqual(toks, ["ok"])

    def test_stream_reassembled_and_extracted(self):
        # End-to-end: stream fenced markdown, accumulate, extract clean C.
        reply = f"Sure!\n```c\n{PROGRAM}\n```\n"
        body = _stream_ndjson(list(reply))  # one char per token, worst case
        with mock.patch("urllib.request.urlopen", return_value=_fake_http(body)):
            full = "".join(llm.rewrite_stream(self.fb))
        self.assertEqual(llm.extract_c(full), PROGRAM)


class TestRewriteOneShot(unittest.TestCase):
    def test_extracts_c_from_chat_response(self):
        body = json.dumps({"message": {"content": f"```c\n{PROGRAM}\n```"}}).encode()
        fb = Feedback("falco", "behavioral rule fired", PROGRAM)
        with mock.patch("urllib.request.urlopen", return_value=_fake_http(body)):
            self.assertEqual(llm.rewrite(fb), PROGRAM)


if __name__ == "__main__":
    unittest.main()
