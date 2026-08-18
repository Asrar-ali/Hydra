"""Hydra dashboard server — HTTP + SSE. Lane 4 owns this.

Skeleton: serves ui/index.html at ``/`` and streams a run at ``/run`` as SSE.
For now ``/run`` runs the loop (fake mode) and replays its rows as ``verdict``
events; the real path streams live per-iteration events, including the
adversary's token stream. See ARCHITECTURE.md §11 for the event contract.

    python3 server.py           # then open http://localhost:8000/
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from common.logging import get_logger
from referee.loop import run_loop

log = get_logger("server")
HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("HYDRA_PORT", "8000"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet default logging
        return

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            return self._serve_file(os.path.join(HERE, "ui", "index.html"), "text/html")
        if self.path.startswith("/run"):
            return self._stream_run()
        self.send_error(404)

    def _serve_file(self, path: str, ctype: str):
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except FileNotFoundError:
            return self.send_error(404)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, event: str, data: dict):
        self.wfile.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
        self.wfile.flush()

    def _stream_run(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        os.environ.setdefault("HYDRA_FAKE", "1")  # TODO(lane4): real live run
        result = run_loop(int(os.environ.get("HYDRA_ITERATION_CAP", "8")))
        for row in result["iterations"]:
            self._sse("verdict", row)
        self._sse("summary", result["summary"])


def main():
    log.info("serving http://localhost:%d/", PORT)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
