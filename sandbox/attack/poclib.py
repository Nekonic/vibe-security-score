"""Attack helper for the disposable PoC container. Mirrors the session/CSRF
semantics of ``scoring.shared.http.DynamicContext`` but stands alone: it only needs
``requests`` on the PYTHONPATH. PoC scripts (``grader/submissions/poc.py``
templates) import ``Client`` and ``render`` from here.

Runs INSIDE the attack container; the target is reached at
``http://host.docker.internal:<port>`` (substituted into the PoC by the session
manager). ``render(resp)`` writes the captured page to ``/poc/out.html`` so the
console can show it in the "browser in a browser" panel (a bind mount lands the
file back on the host).
"""
from __future__ import annotations

import os
import uuid

import requests

# Shipped alongside poclib on the attack image's PYTHONPATH — the single source
# of CSRF handling shared with the grader's scoring.shared.http.DynamicContext.
import csrf

_OUT_DIR = "/poc"
_OUT_FILE = "/poc/out.html"
_TIMEOUT = 8
# Prefer HTML so content-negotiating apps render real pages into the browser
# panel; JSON is still accepted (auth endpoints answer JSON regardless).
_ACCEPT = "text/html,application/json;q=0.9,*/*;q=0.8"
_PW_MARKERS = ('type="password"', "type='password'", "type=password", 'name="password"')


def _json(resp):
    try:
        return resp.json()
    except Exception:
        return None


def _text(resp):
    try:
        return resp.text or ""
    except Exception:
        return ""


def _pick_id(resp):
    """Own user id from an auth JSON response, if the app returns one."""
    j = _json(resp)
    if not isinstance(j, dict):
        return None
    for v in (j.get("id"), j.get("user_id"), (j.get("user") or {}).get("id")
              if isinstance(j.get("user"), dict) else None):
        if isinstance(v, int):
            return v
    return None


class Client:
    """A target session with automatic CSRF handling and lenient POSTs."""

    def __init__(self, target):
        self.target = str(target).rstrip("/")
        self.sess = requests.Session()
        self.sess.headers.update({"Accept": _ACCEPT})
        self._csrf = ""
        self.username = None
        self.email = None
        self.password = "P@ssw0rd!"
        self.user_id = None

    # -- low level -----------------------------------------------------------
    def _url(self, path):
        return f"{self.target}{path}"

    def _remember(self, resp):
        tok = csrf.extract_csrf(resp)
        if tok:
            self._csrf = tok

    def _post(self, url, **kw):
        return self.sess.post(url, timeout=_TIMEOUT, **kw)

    def get(self, path, **kw):
        r = self.sess.get(self._url(path), timeout=_TIMEOUT, **kw)
        self._remember(r)  # seed token from form pages / meta tags
        return r

    def post(self, path, data=None):
        return csrf.post_with_csrf(
            self._post, self._url(path), dict(data or {}),
            get_token=lambda: self._csrf,
            set_token=lambda t: setattr(self, "_csrf", t),
            reseed=lambda: self.get(path),
        )

    # -- high level ----------------------------------------------------------
    def signup(self, username=None, email=None, password="P@ssw0rd!", extra=None):
        """Register (auto-random creds) then log in. ``extra`` injects extra
        fields (e.g. is_admin) to probe mass-assignment."""
        tag = uuid.uuid4().hex[:8]
        self.username = username or f"poc_{tag}"
        self.email = email or f"poc_{tag}@poc.io"
        self.password = password
        try:
            self.get("/signup")  # seed CSRF from the signup form
        except Exception:
            pass
        payload = {"username": self.username, "email": self.email,
                   "name": self.username, "password": self.password}
        if extra:
            payload.update(extra)
        r = self.post("/signup", payload)
        uid = _pick_id(r)
        if uid is not None:
            self.user_id = uid
        self.login()  # establish the authenticated session
        return self

    def login(self, password=None):
        try:
            self.get("/login")
        except Exception:
            pass
        r = self.post("/login", {"username": self.username, "email": self.email,
                                 "password": password or self.password})
        uid = _pick_id(r)
        if uid is not None:
            self.user_id = uid
        return r

    def my_id(self):
        """Own user id: from the auth response if present, else probe
        /users/1..10 for the row that shows our own email."""
        if isinstance(self.user_id, int):
            return self.user_id
        for i in range(1, 11):
            try:
                r = self.get(f"/users/{i}")
            except Exception:
                continue
            if r.status_code == 200 and self.email and self.email in _text(r):
                self.user_id = i
                return i
        return None

    def logged_in(self):
        """Authenticated if /posts shows a logout affordance or has no password
        field (i.e. it isn't a login form)."""
        try:
            r = self.get("/posts")
        except Exception:
            return False
        if r.status_code in (401, 403):
            return False
        body = _text(r).lower()
        if "logout" in body or "로그아웃" in body:
            return True
        return not any(m in body for m in _PW_MARKERS)


def render(resp):
    """Persist the captured page to /poc/out.html for the console's browser panel."""
    try:
        os.makedirs(_OUT_DIR, exist_ok=True)
        with open(_OUT_FILE, "w", encoding="utf-8") as fh:
            fh.write(_text(resp))
    except Exception:
        pass
    return resp
