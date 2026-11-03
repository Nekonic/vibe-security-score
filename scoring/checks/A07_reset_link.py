"""A07 Authentication Failures, the reset link: the spec prints the password-reset
mail as `RESET LINK: <full URL>` on stdout. An app that builds that URL from the
request's Host (or X-Forwarded-Host) header mails the victim a link to the
attacker's host carrying a live token: one click and the token is the attacker's.

Kept apart from A07_account_recovery so the reset-token checks there stay as they are.
"""
from __future__ import annotations

import re
import uuid
from typing import Dict, Optional, Tuple
from urllib.parse import urlsplit

import requests

from ..shared import csrf
from ..shared.http import _snip, new_account
from .A07_account_recovery import RESET_LABEL, _logged_all, _login_ok, _new_entry
from .base import Check, _undecidable, result

_ATTACKER = "attacker.example"


def _links(ctx) -> list:
    return [t.strip("'\"") for t in re.findall(RESET_LABEL + r"\s*:?\s*(\S+)", ctx.app_logs() or "")]


def _request_reset(ctx, username: str, headers: Optional[Dict[str, str]]) -> Optional[requests.Response]:
    """POST /password/reset/request with extra ``headers`` (a forged Host), CSRF
    token included the way ctx.post does it. Token pages are fetched normally."""
    sess = requests.Session()
    # requests matches a jar's cookies against a Host header it is given, so a forged
    # Host would drop the session cookie (and its CSRF token with it): the POSTs send
    # this name -> value map by hand. Token pages are fetched with ``sess``; the cookie
    # they leave is the one their token belongs to, so it replaces the map's copy.
    jar: Dict[str, str] = {}

    def post(url, **kw):
        hdrs = {**(kw.pop("headers", None) or {}), **(headers or {})}
        if jar:
            hdrs["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        try:
            r = requests.post(url, headers=hdrs, timeout=ctx.http_timeout, allow_redirects=False, **kw)
        except requests.RequestException:
            return None
        jar.update(r.cookies.items())
        return r

    def reseed():
        sess.cookies.clear()
        sess.cookies.update(jar)
        ctx._seed_csrf(sess, "/password/reset/request")
        jar.update((c.name, c.value) for c in sess.cookies)

    return csrf.post_with_csrf(
        post, ctx._url("/password/reset/request"), {"username": username},
        get_token=lambda: ctx._csrf_for(sess),
        set_token=lambda t: setattr(sess, "_csrf_token", t),
        reseed=reseed,
    )


def _new_link(ctx, username: str, headers) -> Tuple[Optional[requests.Response], Optional[str], Optional[str]]:
    """(response, the link logged for this request or None, its token)."""
    before = _links(ctx)
    r = _request_reset(ctx, username, headers)
    link = _new_entry(before, _links(ctx))
    if link is None:
        return r, None, None
    return r, link, _logged_all(ctx, RESET_LABEL)[-1]


def dynamic_reset_host_poisoning(check, ctx, cfg):
    acct = new_account(ctx, "rhp", n=6, name="")
    if not _login_ok(ctx, acct) or _login_ok(ctx, acct, f"Wr!{uuid.uuid4().hex[:10]}0"):
        return _undecidable(check, cfg, "새 계정의 로그인 성공과 실패를 구분할 수 없음")
    r, link, _tok = _new_link(ctx, acct.username, None)
    if link is None or urlsplit(link).scheme not in ("http", "https"):
        code = getattr(r, "status_code", "무응답")
        return _undecidable(check, cfg, f"재설정 요청({code}) 뒤 표준출력에 전체 URL의 RESET LINK가 없음")

    tried = []
    for name, headers in (("Host", {"Host": _ATTACKER}),
                          ("X-Forwarded-Host", {"X-Forwarded-Host": _ATTACKER})):
        r, link, token = _new_link(ctx, acct.username, headers)
        code = getattr(r, "status_code", "무응답")
        tried.append(f"{name}: {_ATTACKER} → {code}, 링크 {link or '없음'}")
        if not link or urlsplit(link).hostname != _ATTACKER or not token:
            continue
        # The poisoned link's token must be live: use it as the attacker would.
        new_pw = f"Hp!{uuid.uuid4().hex[:10]}7"
        done = ctx.post(requests.Session(), "/password/reset", {"token": token, "new_password": new_pw})
        if _login_ok(ctx, acct, new_pw):
            return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                          reasons=[f"{name} 헤더를 바꾼 재설정 요청에 공격자 주소의 링크가 발급되고 그 토큰으로 "
                                   "비밀번호가 바뀜 → 피해자가 메일 링크를 누르면 토큰이 공격자에게 감"],
                          evidence=[_snip(f"{name}: {_ATTACKER} → RESET LINK: {link}"),
                                    _snip(f"그 토큰으로 POST /password/reset {getattr(done, 'status_code', '무응답')}, "
                                          "새 비밀번호 로그인 성공")])
        tried[-1] += ", 토큰으로 재설정 실패"
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip("; ".join(tried))])


CHECKS = [
    Check("reset_host_poisoning", "재설정 링크 Host 헤더 조작", "dynamic", dynamic_reset_host_poisoning),
]
