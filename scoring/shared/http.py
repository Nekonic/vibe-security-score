"""Shared plumbing for the dynamic probes: the HTTP/CSRF session context, test
accounts, and response helpers. Probe verdicts themselves live in ``probes.py``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import requests

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


# --- CSRF awareness -------------------------------------------------------
# A correctly CSRF-protected app rejects token-less POSTs (that defense is
# rewarded by the static `csrf_protection` check). The functional/attack probes
# must still be able to act as a legit logged-in user, so they discover the
# session's CSRF token (from a login JSON response, a hidden form field, or a
# <meta> tag) and attach it — otherwise a *secure* app fails the functional gate.
_CSRF_JSON_KEYS = ("csrf_token", "csrf", "csrfToken", "_csrf", "authenticity_token", "token")
_CSRF_FIELD = "csrf_token"
_CSRF_HEADER = "X-CSRF-Token"
_CSRF_HTML_RE = (
    re.compile(r'name=["\']?csrf[_-]?token["\']?[^>]*?value=["\']([^"\']+)', re.I),
    re.compile(r'value=["\']([^"\']+)["\'][^>]*?name=["\']?csrf[_-]?token["\']?', re.I),
    re.compile(r'<meta[^>]*?name=["\']csrf-token["\'][^>]*?content=["\']([^"\']+)', re.I),
)


def _extract_csrf(resp: Optional[requests.Response]) -> Optional[str]:
    """Pull a CSRF token from a response: JSON body first, then hidden input / meta."""
    if resp is None:
        return None
    j = _json_or_none(resp)
    if isinstance(j, dict):
        for k in _CSRF_JSON_KEYS:
            v = j.get(k)
            if isinstance(v, str) and v:
                return v
    body = _body_text(resp)
    if body:
        for rx in _CSRF_HTML_RE:
            m = rx.search(body)
            if m:
                return m.group(1)
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


class ProbeContext:
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
        self.dev = bool(getattr(config, "dev", False))  # gate real CLI tools (sqlmap)
        self.sqlmap_cfg = dict(config.get("tools.sqlmap", {}) or {})

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    @staticmethod
    def _remember_csrf(sess: requests.Session, resp: Optional[requests.Response]) -> None:
        tok = _extract_csrf(resp)
        if tok:
            setattr(sess, "_csrf_token", tok)

    @staticmethod
    def _csrf_for(sess: requests.Session) -> str:
        return getattr(sess, "_csrf_token", "") or ""

    def get(self, sess: requests.Session, path: str, **kw) -> Optional[requests.Response]:
        try:
            r = sess.get(self._url(path), timeout=self.http_timeout, **kw)
        except requests.RequestException:
            return None
        self._remember_csrf(sess, r)  # seed token from form pages / meta tags
        return r

    def _send_post(self, sess, path, data, token):
        """One POST attempt (JSON, form fallback), CSRF token attached both ways."""
        headers = {_CSRF_HEADER: token} if token else None
        body = data if not token else {**data, _CSRF_FIELD: token}
        try:
            r = sess.post(self._url(path), json=body, timeout=self.http_timeout, headers=headers)
        except requests.RequestException:
            return None
        if r is not None and r.status_code in (400, 415, 422):
            try:
                r2 = sess.post(self._url(path), data=body, timeout=self.http_timeout, headers=headers)
                if r2 is not None and r2.status_code < r.status_code:
                    return r2
            except requests.RequestException:
                pass
        return r

    def post(self, sess: requests.Session, path: str, data: Dict[str, Any]) -> Optional[requests.Response]:
        """POST leniently: JSON then form fallback, with the session's CSRF token
        attached (header + field). On a CSRF rejection, fetch a token and retry once
        so a correctly CSRF-protected app still passes the functional/attack probes."""
        r = self._send_post(sess, path, data, self._csrf_for(sess))
        self._remember_csrf(sess, r)  # login responses often return the token
        # CSRF-protected app rejected us: get a token (GET seeds it), retry once.
        if r is not None and r.status_code in (403, 419):
            if not self._csrf_for(sess):
                self.get(sess, path)
            token = self._csrf_for(sess)
            if token:
                r2 = self._send_post(sess, path, data, token)
                self._remember_csrf(sess, r2)
                if r2 is not None and (r2.status_code in (200, 201) or r2.status_code < r.status_code):
                    return r2
        return r


# Admin-page recognition, shared by the access-control and session-forgery probes.
# Markers are only trusted on a 200 response (callers gate on status), so an
# access-denied page that also says "관리자..." never false-positives.
_ADMIN_MARKERS = ("admin dashboard", "운영자", "관리자", "사용자 목록",
                  "admin users", "admin/users", "is_admin", "post_count")


def _looks_like_admin(body: str, j: Any) -> bool:
    low = (body or "").lower()
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


def _low_conf(check_id: str, label: str, weight: float, reason: str, passed: bool = False) -> CheckResult:
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
