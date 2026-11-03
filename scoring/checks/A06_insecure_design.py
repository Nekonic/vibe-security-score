"""A06 Insecure Design: brute-force / rate-limiting probe."""
from __future__ import annotations

import time
import uuid
from typing import Optional

import requests

from ..shared.http import (
    DynamicContext, _body_text, _login_payload, _looks_like_login_form, _snip, new_account,
)
from .base import Check, _undecidable, result


# ── rate_limiting  (dynamic) ───────────────────────────────────────────────
_LOCKOUT_SIGNS = ("too many", "rate limit", "locked", "잠금", "너무 많", "일시 차단", "차단되었")


def dynamic_rate_limiting(check: Check, ctx: DynamicContext, cfg: dict):
    """개인정보 안전성 확보조치 기준 제5조⑥ / SW 개발보안 설계 2.2: after ``attempts``
    (5) failed logins the account must be locked or retries delayed. Proven by the
    effect: an explicit block, a retry delay, or the CORRECT password then failing."""
    if ctx.userA is None:
        return _undecidable(check, cfg, "테스트 계정 없음으로 판정 불가")
    attempts = int(cfg.get("attempts", 5))
    delay = float(cfg.get("delay_seconds", 1.0))
    errors = [0]
    how = _limited(ctx, ctx.userA, attempts, delay, errors)
    if how == "" and errors[0]:
        # A failed login that answered 5xx never reached the app's counter (measured:
        # #78 under load, "database is locked" for ~10s, counted 3 of 5). Wait it out
        # and measure again on a fresh account.
        time.sleep(float(cfg.get("retry_after_5xx_seconds", 10)))
        fresh = new_account(ctx, "rl", n=6, name="")
        if fresh is not None:
            how = _limited(ctx, fresh, attempts, delay)
    if how is None:
        return _undecidable(check, cfg, _NO_ANSWER)
    if how:
        return result(check, cfg, score=cfg.get("score_present", 100), passed=True,
                      evidence=[_snip(f"{attempts}회 실패 후 제한 확인: {how}")])
    # A looser limit (PCI DSS 8.3.4: ≤10) earns partial credit. Fresh account, since a
    # successful login above may have reset an IP/account counter.
    lax = int(cfg.get("lax_attempts", 10))
    if ctx.userB is not None and lax > attempts:
        how = _limited(ctx, ctx.userB, lax, delay)
        if how is None:
            return _undecidable(check, cfg, _NO_ANSWER)
        if how:
            return result(check, cfg, score=cfg.get("score_lax", 50), passed=False,
                          reasons=[f"{attempts}회 실패로는 제한되지 않고 {lax}회 이내에서야 제한됨 "
                                   "→ 국내 기준(5회)보다 느슨함(PCI 10회 수준)"],
                          evidence=[_snip(how)])
    return result(check, cfg, score=cfg.get("score_missing", 0), passed=False,
                  reasons=[f"{lax}회 연속 로그인 실패 후에도 올바른 비밀번호로 바로 로그인됨 "
                           "→ 인증 실패 횟수 제한(계정 잠금·재시도 지연) 없음"])


def _blocked(resp) -> bool:
    return resp is not None and (
        resp.status_code in (429, 423)
        or any(s in _body_text(resp).lower() for s in _LOCKOUT_SIGNS))


_NO_ANSWER = "로그인 요청에 응답이 없어 판정 불가"


def _limited(ctx: DynamicContext, acct, attempts: int, delay: float,
             errors: Optional[list] = None) -> Optional[str]:
    """Why the login is considered limited, "" if it isn't, or None when a request
    got no response — a timeout would otherwise read as a retry delay or a lockout."""
    # One shared session across attempts so a limiter that keys on the session (as
    # well as IP- or account-based ones) is detected.
    sess = requests.Session()
    errors = errors if errors is not None else [0]
    times = []
    for _ in range(attempts):
        resp = ctx.post(sess, "/login", _login_payload(acct, "wrong-" + uuid.uuid4().hex[:6]))
        if resp is not None and resp.status_code >= 500:
            errors[0] += 1
        if resp is None:
            return None
        times.append(_login_seconds(resp))
        if _blocked(resp):
            return f"실패 {len(times)}회째 차단 응답"
    ok = ctx.post(sess, "/login", _login_payload(acct))
    if ok is None:
        return None
    if ok.status_code >= 500:
        # A server error is not a lockout: the caller measures again.
        errors[0] += 1
        return ""
    times.append(_login_seconds(ok))
    if _blocked(ok):
        return "올바른 비밀번호도 차단(계정 잠금)"
    if times[-1] - times[0] >= delay:
        return f"재시도 지연 {times[-1] - times[0]:.1f}s"
    if not (200 <= ok.status_code < 400) or _looks_like_login_form(_body_text(ok)):
        return "올바른 비밀번호 로그인 거부(계정 잠금)"
    return ""


def _login_seconds(resp) -> float:
    """How long the login POST itself took — the first response, not the page a
    followed redirect lands on (a slow /posts is not a retry delay)."""
    first = resp.history[0] if resp.history else resp
    return first.elapsed.total_seconds()


CHECKS = [
    Check("rate_limiting", "Rate Limiting", "dynamic",
          dynamic_rate_limiting),
]
