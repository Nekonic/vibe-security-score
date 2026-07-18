"""A06 Insecure Design: brute-force / rate-limiting probe."""
from __future__ import annotations

import uuid

import requests

from ..shared.http import DynamicContext, _body_text, _login_payload, _snip
from .base import Check, _undecidable, result


# ── rate_limiting  (dynamic) ───────────────────────────────────────────────
_LOCKOUT_SIGNS = ("too many", "rate limit", "locked", "잠금", "너무 많", "일시 차단", "차단되었")


def dynamic_rate_limiting(check: Check, ctx: DynamicContext, cfg: dict):
    if ctx.userA is None:
        return _undecidable(check, cfg, "테스트 계정 없음으로 판정 불가")
    attempts = int(cfg.get("attempts", 8))
    if _lockout_triggered(ctx, attempts):
        return result(check, cfg, score=cfg.get("score_present", 100), passed=True,
                      evidence=[_snip(f"{attempts}회 이내 로그인 시도 차단 확인")])
    return result(check, cfg, score=cfg.get("score_missing", 0), passed=False,
                  reasons=[f"{attempts}회 연속 틀린 로그인에도 차단/지연 없음 → 무차별 대입 방어 부재"])


def _lockout_triggered(ctx: DynamicContext, attempts: int) -> bool:
    # One shared session across attempts so a limiter that keys on the session (as
    # well as IP- or account-based ones) is detected — a fresh session per try would
    # miss session-scoped throttling and falsely report "no limiting".
    sess = requests.Session()
    for _ in range(attempts):
        resp = ctx.post(sess, "/login", _login_payload(ctx.userA, "wrong-" + uuid.uuid4().hex[:6]))
        if resp is None:
            continue
        if resp.status_code in (429, 423) or any(s in _body_text(resp).lower() for s in _LOCKOUT_SIGNS):
            return True
    return False


CHECKS = [
    Check("rate_limiting", "무차별 대입 방어(Rate limiting)", "dynamic",
          dynamic_rate_limiting),
]
