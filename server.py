"""Hydra dashboard server — HTTP + SSE. Lane 4 owns this.

    GET /                serve the dashboard
    GET /run            run the loop live, stream events as SSE
                        query: iterations=N, fake=1 (no container), record=1,
                               mode=metamorphic|promptlock (default metamorphic)
    GET /replay         replay a recorded run (replay.json) with live pacing
    GET /health         liveness

Event vocabulary matches ARCHITECTURE.md §11. Run:

    python3 server.py           # then open http://localhost:8000/
"""
from __future__ import annotations

import glob
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from common.logging import get_logger
from referee.loop import run_events

log = get_logger("server")
HERE = os.path.dirname(os.path.abspath(__file__))
REPLAY = os.path.join(HERE, "replay.json")
SAMPLE_DIR = os.path.join(HERE, "sample")
PORT = int(os.environ.get("HYDRA_PORT", "8000"))

# Labels shown in the UI dropdown; keys are stem names (without .c)
_SEED_LABELS = {
    "seed":        "XOR-cipher (default)",
    "seed_mmap":   "mmap I/O",
    "seed_walker": "dir-walker",
}


def _available_seeds() -> list[dict]:
    """Return seeds in a stable order: default first, rest alphabetical."""
    stems = sorted(
        os.path.splitext(os.path.basename(p))[0]
        for p in glob.glob(os.path.join(SAMPLE_DIR, "seed*.c"))
    )
    # ensure default is first
    if "seed" in stems:
        stems = ["seed"] + [s for s in stems if s != "seed"]
    return [{"name": s, "label": _SEED_LABELS.get(s, s)} for s in stems]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # quiet default logging
        return

    def do_GET(self):
        route = urlparse(self.path)
        params = parse_qs(route.query)
        if route.path in ("/", "/index.html"):
            return self._serve_file(os.path.join(HERE, "ui", "index.html"), "text/html")
        if route.path == "/health":
            return self._json({"ok": True})
        if route.path == "/seeds":
            return self._json(_available_seeds())
        if route.path == "/run":
            return self._run(params)
        if route.path == "/replay":
            return self._replay()
        self.send_error(404)

    # --- helpers ----------------------------------------------------------

    def _serve_file(self, path, ctype):
        try:
            with open(path, "rb") as fh:
                body = fh.read()
        except FileNotFoundError:
            return self.send_error(404)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def _open_sse(self):
        # Close the connection when the stream ends so clients (and curl) don't
        # hang waiting; the browser EventSource closes itself on `summary`.
        self.close_connection = True
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

    def _send(self, name, data):
        self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
        self.wfile.flush()

    # --- routes -----------------------------------------------------------

    def _run(self, params):
        cap = int(params.get("iterations", ["6"])[0])
        mode = params.get("mode", ["metamorphic"])[0]
        if mode not in ("metamorphic", "promptlock"):
            mode = "metamorphic"
        if params.get("fake", ["0"])[0] == "1":
            os.environ["HYDRA_FAKE"] = "1"
        else:
            os.environ.pop("HYDRA_FAKE", None)
        record = params.get("record", ["0"])[0] == "1"
        custom_prompt = params.get("prompt", [None])[0] or None

        allowed = {s["name"] for s in _available_seeds()}
        seed_name = params.get("seed", ["seed"])[0]
        if seed_name not in allowed:
            seed_name = "seed"

        self._open_sse()
        collected = []
        try:
            for name, data in run_events(cap, mode=mode, custom_prompt=custom_prompt,
                                         seed_name=seed_name):
                collected.append([name, data])
                self._send(name, data)
        except BrokenPipeError:
            return  # client disconnected
        if record:
            with open(REPLAY, "w", encoding="utf-8") as fh:
                json.dump(collected, fh)
            log.info("recorded %d events -> replay.json", len(collected))

    def _replay(self):
        try:
            with open(REPLAY, encoding="utf-8") as fh:
                events = json.load(fh)
        except FileNotFoundError:
            return self.send_error(404, "no replay.json (run with ?record=1 first)")
        self._open_sse()
        try:
            for name, data in events:
                self._send(name, data)
                time.sleep(0.012 if name == "rewrite_token" else 0.35)
        except BrokenPipeError:
            return


def main():
    log.info("Hydra dashboard on http://localhost:%d/", PORT)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
