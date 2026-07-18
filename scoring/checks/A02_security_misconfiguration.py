"""A02 Security Misconfiguration: debug mode and security-header static checks,
plus the runtime transport/response-hardening probe.
"""
from __future__ import annotations

import re
from typing import List

import requests

from ..shared.http import _login_payload, _snip
from ..shared.sources import _iter_lines, _joined
from .base import Check, _undecidable, result


# ── debug_true  (static) ───────────────────────────────────────────────────
_DEBUG_TRUE = re.compile(
    r"""(debug\s*=\s*True)|(\bDEBUG\s*=\s*True\b)|(\[\s*['"]DEBUG['"]\s*\]\s*=\s*True)""",
    re.VERBOSE,
)


def check_debug_true(check, sctx, cfg):
    penalty = float(cfg.get("penalty_per_finding", 100))
    reasons: List[str] = []
    evidence: List[str] = []
    for path, lineno, line in _iter_lines(sctx.sources):
        if line.lstrip().startswith("#"):
            continue
        if _DEBUG_TRUE.search(line):
            reasons.append(f"{path}:{lineno} debug=True 사용")
            evidence.append(f"{path}:{lineno}: {line.strip()}")
    return result(check, cfg, score=100.0 - penalty * len(reasons),
                  passed=not reasons, reasons=reasons, evidence=evidence)


# ── security_headers  (static) ─────────────────────────────────────────────
_HEADERS = {
    "Content-Security-Policy": re.compile(r"""Content-Security-Policy|content_security_policy|['"]CSP['"]""", re.IGNORECASE),
    "X-Frame-Options": re.compile(r"""X-Frame-Options|frame_options""", re.IGNORECASE),
    "Strict-Transport-Security": re.compile(r"""Strict-Transport-Security|strict_transport_security|\bhsts\b""", re.IGNORECASE),
    "X-Content-Type-Options": re.compile(r"""X-Content-Type-Options|content_type_options""", re.IGNORECASE),
}
# A mechanism that actually emits the header: an after_request hook, Talisman, or
# setting it directly on a response (resp.headers['X-Frame-Options'] = ..., or
# add_header). Without this, a bare header NAME in the source isn't proof it's sent.
_HEADER_MECHANISM = re.compile(
    r"""after_request|Talisman|\.headers\s*\[|\.headers\.setdefault|add_header|set_header""",
    re.IGNORECASE,
)


def check_security_headers(check, sctx, cfg):
    baseline = float(cfg.get("baseline", 20))
    per_header = float(cfg.get("score_per_header", 20))

    joined = _joined(sctx.sources)
    has_mechanism = bool(_HEADER_MECHANISM.search(joined))
    talisman = bool(re.search(r"""Talisman""", joined))  # applies a strong default header set
    present = []
    evidence: List[str] = []
    for name, pat in _HEADERS.items():
        if talisman or (pat.search(joined) and has_mechanism):
            present.append(name)
            evidence.append(name)

    missing = [h for h in _HEADERS if h not in present]
    reasons = [f"{m} 보안 헤더 미설정" for m in missing]
    return result(check, cfg, score=baseline + per_header * len(present),
                  passed=not missing, reasons=reasons, evidence=evidence)


# ── transport_security  (dynamic) — runtime response hardening ─────────────
_SEC_HEADERS = ("content-security-policy", "x-frame-options",
                "strict-transport-security", "x-content-type-options")
_COOKIE_ATTRS = ("secure", "httponly", "samesite")


def dynamic_transport_security(check, ctx, cfg):
    sess = ctx.userA.session if ctx.userA is not None else requests.Session()
    # Log in so a session cookie is issued, then inspect the response.
    if ctx.userA is not None:
        ctx.post(sess, "/login", _login_payload(ctx.userA))
    r = ctx.get(sess, "/posts")
    if r is None:
        return _undecidable(check, cfg, "응답 없음으로 판정 불가")

    headers_low = {k.lower(): v for k, v in r.headers.items()}
    present_headers = [h for h in _SEC_HEADERS if h in headers_low]
    set_cookie = "; ".join(
        v for k, v in r.headers.items() if k.lower() == "set-cookie"
    ) or headers_low.get("set-cookie", "")
    cookie_low = set_cookie.lower()
    present_cookie = [a for a in _COOKIE_ATTRS if a in cookie_low] if set_cookie else []

    max_points = len(_SEC_HEADERS) + len(_COOKIE_ATTRS)
    got = len(present_headers) + len(present_cookie)
    reasons: List[str] = []
    missing_h = [h for h in _SEC_HEADERS if h not in present_headers]
    if missing_h:
        reasons.append("응답 보안 헤더 누락: " + ", ".join(missing_h))
    if set_cookie:
        missing_c = [a for a in _COOKIE_ATTRS if a not in present_cookie]
        if missing_c:
            reasons.append("세션 쿠키 플래그 누락: " + ", ".join(missing_c))
    return result(check, cfg, score=100.0 * got / max_points, passed=not reasons,
                  reasons=reasons,
                  evidence=[_snip(f"headers={present_headers} cookie={present_cookie}")])


CHECKS = [
    Check("debug_true", "디버그 모드", "static", check_debug_true),
    Check("security_headers", "보안 헤더", "static", check_security_headers),
    Check("transport_security", "전송/응답 보안(헤더·쿠키 플래그)", "dynamic",
          dynamic_transport_security),
]
