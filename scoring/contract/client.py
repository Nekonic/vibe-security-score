"""Browser-like HTTP client for the functional contract. It carries the app's CSRF
token (JSON body / hidden input / <meta>) on every state-changing request and keeps
Secure cookies usable over the sandbox's plain HTTP — so a correctly hardened app is
never failed for being hardened. It tests behavior only, never a denial. A
``deadline`` (``time.monotonic()``) bounds every request: past it nothing is sent."""
from __future__ import annotations

import io
import time
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests

from ..shared.csrf import CSRF_FIELD, CSRF_HEADERS, REJECT_STATUSES, extract_csrf, retry_wins

_SEED_PATHS = ("/csrf", "/", "/login", "/posts")
_MAX_REDIRECTS = 10


class Client:
    def __init__(self, base_url: str, timeout: float = 15.0, deadline: Optional[float] = None):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.deadline = deadline

    def session(self) -> requests.Session:
        s = requests.Session()
        s.headers["Accept"] = "text/html,application/xhtml+xml,*/*;q=0.8"
        s._csrf = ""  # type: ignore[attr-defined]
        return s

    def _timeout(self) -> Optional[float]:
        if self.deadline is None:
            return self.timeout
        left = self.deadline - time.monotonic()
        return min(self.timeout, left) if left > 0 else None

    def raw(self, sess: requests.Session, method: str, path: str,
            allow_redirects: bool = True, **kw: Any) -> Optional[requests.Response]:
        """One request; redirects are followed here, hop by hop, so the Secure flag
        is cleared on every cookie a hop sets before the next hop is sent (requests'
        own redirect loop would drop a Secure session cookie over plain HTTP)."""
        url = self.base + path
        try:
            for _ in range(_MAX_REDIRECTS + 1):
                timeout = self._timeout()
                if timeout is None:
                    return None
                r = sess.request(method, url, timeout=timeout, allow_redirects=False, **kw)
                for c in sess.cookies:
                    c.secure = False
                if not allow_redirects or not r.is_redirect:
                    break
                url = urljoin(url, r.headers["Location"])
                # requests' own method rules (Session.rebuild_method)
                if (r.status_code in (302, 303) and method != "HEAD") or (r.status_code == 301 and method == "POST"):
                    method, kw = "GET", {k: v for k, v in kw.items() if k == "headers"}
            else:
                return None  # too many redirects, as requests would raise
        except requests.RequestException:
            return None
        tok = extract_csrf(r)
        if tok:
            sess._csrf = tok  # type: ignore[attr-defined]
        return r

    def seed(self, sess: requests.Session, path: str) -> None:
        for p in _SEED_PATHS + (path,):
            if sess._csrf:  # type: ignore[attr-defined]
                return
            self.raw(sess, "GET", p)

    def get(self, sess: requests.Session, path: str) -> Optional[requests.Response]:
        return self.raw(sess, "GET", path)

    def send(self, sess: requests.Session, method: str, path: str, *,
             json: Optional[Dict[str, Any]] = None, data: Optional[Dict[str, Any]] = None,
             files: Optional[Dict[str, tuple]] = None,
             allow_redirects: bool = True) -> Optional[requests.Response]:
        """State-changing request with the session's CSRF token (header + field);
        on a rejection, re-seed a token once and retry."""
        page = path.split("/comments")[0] if "/comments" in path else path

        def attempt() -> Optional[requests.Response]:
            tok = sess._csrf  # type: ignore[attr-defined]
            kw: Dict[str, Any] = {"headers": {h: tok for h in CSRF_HEADERS} if tok else {}}
            if json is not None:
                kw["json"] = {**json, CSRF_FIELD: tok} if tok else json
            else:
                body = dict(data or {})
                if tok:
                    body[CSRF_FIELD] = tok
                kw["data"] = body
                if files:
                    kw["files"] = {k: (name, io.BytesIO(content), ctype)
                                   for k, (name, content, ctype) in files.items()}
            return self.raw(sess, method, path, allow_redirects=allow_redirects, **kw)

        if not sess._csrf:  # type: ignore[attr-defined]
            self.seed(sess, page)
        r = attempt()
        if r is not None and r.status_code in REJECT_STATUSES:
            prev = sess._csrf  # type: ignore[attr-defined]
            sess._csrf = ""  # type: ignore[attr-defined]
            self.seed(sess, page)
            if not sess._csrf:  # type: ignore[attr-defined]
                sess._csrf = prev  # type: ignore[attr-defined]
            r2 = attempt()
            if retry_wins(r, r2):
                r = r2
        return r
