"""A06 Insecure Design: brute-force / rate-limiting probe."""
from __future__ import annotations

import uuid
from typing import Any, Dict

import requests

from ..models import CheckResult
from ..shared.http import ProbeContext, _body_text, _login_payload, _low_conf, _snip
from .base import Control


# rate_limiting — repeated wrong logins must be throttled/locked.
_LOCKOUT_SIGNS = ("too many", "rate limit", "locked", "잠금", "너무 많", "일시 차단", "차단되었")


def probe_rate_limiting(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 8))
    label = "무차별 대입 방어(Rate limiting)"
    try:
        if ctx.userA is None:
            return _low_conf("rate_limiting", label, weight, "테스트 계정 없음으로 판정 불가")
        attempts = int(cfg.get("attempts", 8))
        blocked = False
        for _ in range(attempts):
            r = ctx.post(requests.Session(), "/login",
                         _login_payload(ctx.userA, "wrong-" + uuid.uuid4().hex[:6]))
            if r is None:
                continue
            if r.status_code in (429, 423) or any(s in _body_text(r).lower() for s in _LOCKOUT_SIGNS):
                blocked = True
                break
        if blocked:
            return CheckResult(
                check_id="rate_limiting", category="dynamic", label=label,
                score=float(cfg.get("score_present", 100)), weight=weight, passed=True,
                penalty_reasons=[], evidence=[_snip(f"{attempts}회 이내 로그인 시도 차단 확인")],
            )
        return CheckResult(
            check_id="rate_limiting", category="dynamic", label=label,
            score=float(cfg.get("score_missing", 0)), weight=weight, passed=False,
            penalty_reasons=[f"{attempts}회 연속 틀린 로그인에도 차단/지연 없음 → 무차별 대입 방어 부재"],
            evidence=[],
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("rate_limiting", label, weight, f"rate limiting 프로브 예외: {exc}")


CONTROLS = [
    Control("rate_limiting", "무차별 대입 방어(Rate limiting)", "dynamic", probe_rate_limiting),
]
