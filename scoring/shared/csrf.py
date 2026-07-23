"""CSRF-aware POST, shared by the grader's dynamic probes
(``scoring.shared.http.DynamicContext``) and the attack container's ``poclib``.

Kept dependency-free (``requests`` + stdlib) and free of intra-package imports so
the attack image can drop this one file onto its PYTHONPATH and ``import csrf``
directly — the two callers can never drift apart.

A correctly CSRF-protected app rejects a token-less state-changing POST. To still
act as a legit logged-in user, discover the session's token (login JSON, hidden
form field, or <meta> tag) and attach it. Rejections come back as 403/419, but
some apps ``abort(400)`` — so on any of those, discard the (possibly stale, apps
rotate on login) token, reseed a fresh one, and retry once.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, Optional

import requests

CSRF_JSON_KEYS = ("csrf_token", "csrf", "csrfToken", "_csrf", "authenticity_token", "token")
CSRF_FIELD = "csrf_token"
CSRF_HEADER = "X-CSRF-Token"
# Field/meta NAME variants apps use for the CSRF token. Crucially this must include
# ``_csrf`` (a very common hand-rolled name and one we ALREADY accept as a JSON key):
# recognizing it only in JSON but not in HTML forms meant a form-only app's token
# could never be re-seeded from a GET page — poisoning the whole session after one
# rejection. Also cover Django's ``csrfmiddlewaretoken`` and Rails' ``authenticity_token``.
_CSRF_NAME = r"(?:_?csrf(?:[_-]?token)?|csrfmiddlewaretoken|authenticity_token)"
_CSRF_HTML_RE = (
    re.compile(r'name=["\']?' + _CSRF_NAME + r'["\']?[^>]*?value=["\']([^"\']+)', re.I),
    re.compile(r'value=["\']([^"\']+)["\'][^>]*?name=["\']?' + _CSRF_NAME + r'["\']?', re.I),
    re.compile(r'<meta[^>]*?name=["\']' + _CSRF_NAME + r'["\'][^>]*?content=["\']([^"\']+)', re.I),
)

_REJECT_STATUSES = (400, 403, 419)   # token-less POST rejected (some apps abort 400)
_RETRY_JSON_STATUSES = (400, 415, 422)  # JSON not accepted -> retry as form


def _json(resp: Optional[requests.Response]) -> Optional[Any]:
    if resp is None:
        return None
    try:
        return resp.json()
    except Exception:
        return None


def _text(resp: Optional[requests.Response]) -> str:
    if resp is None:
        return ""
    try:
        return resp.text or ""
    except Exception:
        return ""


def extract_csrf(resp: Optional[requests.Response]) -> Optional[str]:
    """Pull a CSRF token from a response: JSON body first, then hidden input / meta."""
    j = _json(resp)
    if isinstance(j, dict):
        for k in CSRF_JSON_KEYS:
            v = j.get(k)
            if isinstance(v, str) and v:
                return v
    body = _text(resp)
    if body:
        for rx in _CSRF_HTML_RE:
            m = rx.search(body)
            if m:
                return m.group(1)
    return None


def send_post(post: Callable[..., Optional[requests.Response]], url: str,
              data: Dict[str, Any], token: str) -> Optional[requests.Response]:
    """One POST attempt: JSON first, form fallback if JSON is refused, with the
    token attached both as a header and a field. ``post`` is a session's POST
    bound with its timeout: ``post(url, json=..., data=..., headers=...)``."""
    headers = {CSRF_HEADER: token} if token else None
    body = data if not token else {**data, CSRF_FIELD: token}
    r = post(url, json=body, headers=headers)
    if r is not None and r.status_code in _RETRY_JSON_STATUSES:
        r2 = post(url, data=body, headers=headers)
        if r2 is not None and r2.status_code < r.status_code:
            return r2
    return r


def post_with_csrf(post: Callable[..., Optional[requests.Response]], url: str,
                   data: Dict[str, Any], *, get_token: Callable[[], str],
                   set_token: Callable[[str], None],
                   reseed: Callable[[], None]) -> Optional[requests.Response]:
    """POST with the session's CSRF token; on rejection discard the stale token,
    ``reseed`` a fresh one, and retry once. ``reseed`` GETs token-bearing pages
    (the caller decides which)."""
    r = send_post(post, url, data, get_token())
    tok = extract_csrf(r)
    if tok:
        set_token(tok)  # login responses often return the next token
    if r is not None and r.status_code in _REJECT_STATUSES:
        # A rejection MIGHT be a stale token — but 400 is also what apps return for
        # ordinary validation failures (bad file type, missing field), which have
        # nothing to do with CSRF. Discarding the token then failing to re-seed a new
        # one (e.g. the token only lived in a login JSON, not on GET pages) would blank
        # the session's token permanently and 403 every later request. So keep the
        # PRIOR token as a fallback: only replace it if re-seeding actually finds one.
        prev = get_token()
        set_token("")
        reseed()
        token = get_token() or prev
        if token:
            set_token(token)
            r2 = send_post(post, url, data, token)
            tok2 = extract_csrf(r2)
            if tok2:
                set_token(tok2)
            if r2 is not None and (r2.status_code in (200, 201) or r2.status_code < r.status_code):
                return r2
    return r
