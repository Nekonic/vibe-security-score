"""Grader-side SSRF callback listener.

A tiny HTTP server the dynamic SSRF probe hands to the graded app as a target URL.
If the app fetches it server-side, the request lands here and we record the token —
proof the server made an outbound request to an attacker-chosen PRIVATE/host address
(the listener is reached via the container's bridge gateway, a private range a proper
SSRF filter blocks). Records only; serves a trivial 200. Runs on a random free port
for the duration of one dynamic run.
"""
from __future__ import annotations

import http.server
import threading
from typing import Optional, Set


class _Handler(http.server.BaseHTTPRequestHandler):
    def _record(self) -> None:
        # token = first path segment, e.g. GET /ssrf-abc123/meta -> "ssrf-abc123"
        token = self.path.lstrip("/").split("/", 1)[0].split("?", 1)[0]
        if token:
            self.server.hits.add(token)  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _record
    do_POST = _record
    do_HEAD = _record

    def log_message(self, *_args) -> None:  # silence stderr access log
        pass


class SSRFCallback:
    """Context manager: starts a background HTTP listener, exposes ``url_for`` /
    ``was_hit``. Never raises on start failure — ``port is None`` then and the probe
    treats a missing callback as 'undecidable' (falls back to static ssrf_sink)."""

    def __init__(self) -> None:
        self._srv: Optional[http.server.ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.port: Optional[int] = None

    def __enter__(self) -> "SSRFCallback":
        try:
            srv = http.server.ThreadingHTTPServer(("0.0.0.0", 0), _Handler)
            srv.hits = set()  # type: ignore[attr-defined]
            self._srv = srv
            self.port = srv.server_address[1]
            self._thread = threading.Thread(target=srv.serve_forever, daemon=True)
            self._thread.start()
        except OSError:
            self._srv = None
            self.port = None
        return self

    def __exit__(self, *_exc) -> bool:
        if self._srv is not None:
            try:
                self._srv.shutdown()
                self._srv.server_close()
            except Exception:
                pass
        return False

    @property
    def hits(self) -> Set[str]:
        return self._srv.hits if self._srv is not None else set()  # type: ignore[attr-defined]

    def url_for(self, token: str, host: str) -> str:
        return f"http://{host}:{self.port}/{token}"

    def was_hit(self, token: str) -> bool:
        return token in self.hits
