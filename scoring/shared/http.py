"""Shared plumbing for the dynamic probes: the HTTP/CSRF session context, test
accounts, and response helpers. Probe verdicts themselves live in ``probes.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Dict, Optional

import requests

from . import csrf
from ..config import Config
from ..models import CheckResult

_EVIDENCE_MAX = 400


def _snip(text: str, limit: int = _EVIDENCE_MAX) -> str:
    text = text or ""
    if len(text) > limit:
        return text[:limit] + "…(truncated)"
    return text


def _body_text(resp: Optional[requests.Response]) -> str:
    if resp is None:
        return ""
    try:
        return resp.text or ""
    except Exception:
        return ""


def _json_or_none(resp: Optional[requests.Response]) -> Optional[Any]:
    if resp is None:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def _signup_payload(acct: "Account") -> Dict[str, Any]:
    # Send username+email+name so both username- and email-based apps accept it.
    return {"username": acct.username, "email": acct.email,
            "name": acct.name, "password": acct.password}


def _login_payload(acct: "Account", password: Optional[str] = None) -> Dict[str, Any]:
    return {"username": acct.username, "email": acct.email,
            "password": acct.password if password is None else password}


def _post_payload(title: str, content: str) -> Dict[str, Any]:
    # Apps split on the post-body field name (content/body/text); send all so the
    # post is actually created regardless — otherwise create fails, functional
    # false-passes via a redirect, and stored_xss/sqli silently test nothing.
    return {"title": title, "content": content, "body": content, "text": content}


def create_post_id(ctx, sess: requests.Session, title: str, content: str) -> Optional[int]:
    """Create a post and return its id — from the create response JSON, else by
    matching ``content`` (use a unique value) to a ``/posts/<id>`` link the listing
    exposes (form apps that redirect). ``None`` if the id can't be pinned. Shared by
    the BOLA and comment-XSS probes."""
    r = ctx.post(sess, "/posts", _post_payload(title, content))
    if r is None or r.status_code not in (200, 201):
        return None
    j = _json_or_none(r)
    if isinstance(j, dict):
        for key in ("id", "post_id", "pk"):
            if isinstance(j.get(key), int):
                return j[key]
    listing = _body_text(ctx.get(sess, "/posts"))
    if content not in listing:
        return None
    for pid in sorted({int(n) for n in re.findall(r"/posts/(\d+)", listing)}, reverse=True):
        if content in _body_text(ctx.get(sess, f"/posts/{pid}")):
            return pid
    return None


_LOGIN_FORM_MARKERS = ('type="password"', "type='password'", "type=password",
                       'name="password"', "name='password'")


def _looks_like_login_form(text: str) -> bool:
    # Form apps re-render the login page with HTTP 200 on a failed login, so
    # status alone can't tell acceptance from rejection — a password input means
    # the user was NOT logged in.
    t = (text or "").lower()
    return any(m in t for m in _LOGIN_FORM_MARKERS)


@dataclass
class Account:
    email: str
    password: str
    name: str = ""
    username: str = ""
    session: requests.Session = field(default_factory=requests.Session)
    user_id: Optional[int] = None
    is_admin: bool = False

    def __post_init__(self):
        # Apps split between `email` and `username` login; derive a username so
        # both contracts work (we send both fields in every auth request).
        if not self.username:
            self.username = self.email.split("@", 1)[0] if self.email else self.name


class DynamicContext:
    def __init__(self, base_url: str, config: Config):
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.http_timeout = float(config.get("timeouts.http_request", 8))

        probes = config.get("probes", {}) or {}
        accts = probes.get("test_accounts", []) or []
        self.userA = Account(**{k: accts[0][k] for k in ("email", "password", "name") if k in accts[0]}) if accts else None
        self.userB = Account(**{k: accts[1][k] for k in ("email", "password", "name") if k in accts[1]}) if len(accts) > 1 else None
        adm = probes.get("admin_account", {}) or {}
        self.admin = Account(email=adm.get("email", ""), password=adm.get("password", ""), name=adm.get("name", "Admin"))
        self.admin.is_admin = True

        self.xss_payload = str(probes.get("xss_payload", "<script>alert('xss-{marker}')</script>"))
        # Multiple payloads cover several sink contexts (script/img/svg/attr/js-url).
        self.xss_payloads = [str(p) for p in (probes.get("xss_payloads") or [self.xss_payload])]
        self.sqli_payloads = list(probes.get("sqli_payloads", []) or [])
        self.sqli_auth_bypass = list(probes.get("sqli_auth_bypass", []) or [])
        # SECRET_KEY literals extracted from the app source (set by run_dynamic).
        # session_forgery forges with these too, so a HARDCODED key is proven
        # forgeable (the grader knows its exact value), not just statically flagged.
        self.source_secrets: list = []
        self.dev = bool(getattr(config, "dev", False))  # gate real CLI tools (sqlmap)
        self.sqlmap_cfg = dict(config.get("tools.sqlmap", {}) or {})
        # Endpoints that hand out a CSRF token (JSON body / form / <meta>), tried in
        # order to seed a token when a state-changing POST is rejected for lacking one.
        self._csrf_paths = [str(p) for p in (probes.get("csrf_paths") or ["/csrf", "/", "/login"])]

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    @staticmethod
    def _desecure(sess: requests.Session) -> None:
        """The graded app runs over plain HTTP in the sandbox. A hardened app that
        sets SESSION_COOKIE_SECURE=True would otherwise have its session cookie
        withheld over HTTP → login wouldn't persist → the whole dynamic suite would
        falsely fail a CORRECTLY-hardened app. Clear the Secure flag on stored
        cookies so the grader still exchanges them over HTTP (no false penalty)."""
        for c in sess.cookies:
            if getattr(c, "secure", False):
                c.secure = False

    @staticmethod
    def _remember_csrf(sess: requests.Session, resp: Optional[requests.Response]) -> None:
        tok = csrf.extract_csrf(resp)
        if tok:
            setattr(sess, "_csrf_token", tok)

    @staticmethod
    def _csrf_for(sess: requests.Session) -> str:
        return getattr(sess, "_csrf_token", "") or ""

    def _bound_post(self, sess: requests.Session):
        def _post(url, **kw):
            try:
                return sess.post(url, timeout=self.http_timeout, **kw)
            except requests.RequestException:
                return None
        return _post

    def get(self, sess: requests.Session, path: str, **kw) -> Optional[requests.Response]:
        try:
            r = sess.get(self._url(path), timeout=self.http_timeout, **kw)
        except requests.RequestException:
            return None
        self._desecure(sess)  # keep Secure cookies usable over the sandbox's HTTP
        self._remember_csrf(sess, r)  # seed token from form pages / meta tags
        return r

    def _seed_csrf(self, sess: requests.Session, path: str) -> None:
        """GET token-bearing endpoints until the session holds a CSRF token."""
        for p in self._csrf_paths + [path]:
            if self._csrf_for(sess):
                return
            self.get(sess, p)

    def post(self, sess: requests.Session, path: str, data: Dict[str, Any]) -> Optional[requests.Response]:
        r = csrf.post_with_csrf(
            self._bound_post(sess), self._url(path), data,
            get_token=lambda: self._csrf_for(sess),
            set_token=lambda t: setattr(sess, "_csrf_token", t),
            reseed=lambda: self._seed_csrf(sess, path),
        )
        self._desecure(sess)  # keep Secure cookies usable over the sandbox's HTTP
        return r

    def put(self, sess: requests.Session, path: str, data: Dict[str, Any]) -> Optional[requests.Response]:
        return self._csrf_send("PUT", sess, path, data)

    def patch(self, sess: requests.Session, path: str, data: Dict[str, Any]) -> Optional[requests.Response]:
        return self._csrf_send("PATCH", sess, path, data)

    def delete(self, sess: requests.Session, path: str,
               data: Optional[Dict[str, Any]] = None) -> Optional[requests.Response]:
        return self._csrf_send("DELETE", sess, path, data or {})

    def _csrf_send(self, method: str, sess: requests.Session, path: str,
                   data: Dict[str, Any]) -> Optional[requests.Response]:
        """State-changing PUT/PATCH/DELETE with the session's CSRF token (same
        discovery/retry as ``post``). Carrying the token means object-authorization
        probing tests AUTHORIZATION on a CSRF-protected app, not CSRF."""
        def _bound(url, **kw):
            try:
                return sess.request(method, url, timeout=self.http_timeout, **kw)
            except requests.RequestException:
                return None

        r = csrf.post_with_csrf(
            _bound, self._url(path), data,
            get_token=lambda: self._csrf_for(sess),
            set_token=lambda t: setattr(sess, "_csrf_token", t),
            reseed=lambda: self._seed_csrf(sess, path),
        )
        self._desecure(sess)
        return r


# Admin-page recognition, shared by the access-control and session-forgery probes.
# Content markers that indicate actual admin data. Nav-link strings like
# "admin/users" are deliberately EXCLUDED — they appear in a shared navbar visible
# to everyone and would false-positive; the probes already hit the admin PATHS.
_ADMIN_MARKERS = ("admin dashboard", "관리자 대시보드", "운영자", "관리자", "사용자 목록",
                  "is_admin", "post_count")
# A soft access-denied page rendered with HTTP 200 (common) can contain "관리자"
# ("관리자 권한이 필요합니다"); these phrases mean the viewer is NOT an admin, so a
# match here vetoes the admin verdict (kills the denial-page false positive).
_ADMIN_DENY = ("권한이 없", "권한이 필요", "접근 권한", "접근이 거부", "로그인이 필요",
               "login required", "please log in", "forbidden", "unauthorized",
               "access denied", "not authorized")


def _looks_like_admin(body: str, j: Any) -> bool:
    low = (body or "").lower()
    if any(d.lower() in low for d in _ADMIN_DENY):
        return False  # explicit denial/login page — not real admin content
    if any(m.lower() in low for m in _ADMIN_MARKERS):
        return True
    if isinstance(j, dict) and isinstance(j.get("users"), list) and j["users"]:
        return True
    return False


def _is_html_response(resp: Optional[requests.Response]) -> bool:
    """XSS only matters in an HTML context. Apps that content-negotiate return JSON
    for ``Accept: */*``; a raw payload echoed in a JSON *data* response is not XSS,
    so the XSS probes request HTML and only judge genuine HTML responses."""
    if resp is None:
        return False
    return "html" in resp.headers.get("Content-Type", "").lower()


def _scored_zero(check_id: str, label: str, weight: float, reason: str, passed: bool = False) -> CheckResult:
    """A check we could NOT reliably test. Marked ``skipped`` so aggregation
    EXCLUDES it — scoring an untestable check as vulnerable would falsely penalize
    a defended app. Still reported so the operator sees why it was skipped."""
    return CheckResult(
        check_id=check_id,
        category="dynamic",
        label=label,
        score=0.0,
        weight=weight,
        passed=passed,
        skipped=True,
        penalty_reasons=[f"검사 생략(판정 불가): {reason}"],
        evidence=[],
    )
