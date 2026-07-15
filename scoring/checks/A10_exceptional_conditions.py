"""A10 Mishandling of Exceptional Conditions: malformed input must not leak stack
traces / the debugger (dynamic probe).
"""
from __future__ import annotations

import uuid
from typing import Any, Dict

import requests

from ..models import CheckResult
from ..shared.http import DynamicContext, _body_text, _scored_zero, _snip
from .base import Check


_DEBUG_SIGNS = (
    "traceback (most recent call last)", "werkzeug debugger", "werkzeug.debug",
    "/__debugger__", "this is the werkzeug", "sqlalchemy", "file \"/app",
)


def dynamic_verbose_errors(ctx: DynamicContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 8))
    label = "오류 처리(스택트레이스 노출)"
    try:
        sess = ctx.userA.session if ctx.userA is not None else requests.Session()
        probes_reqs = [
            ("GET", "/users/999999999", None),
            ("GET", "/posts", {"sort": "no_such_col_" + uuid.uuid4().hex[:6]}),
            ("POST", "/posts", {"title": None}),
            ("GET", "/search", {"q": "%' "}),
        ]
        for method, path, data in probes_reqs:
            if method == "GET":
                r = ctx.get(sess, path, params=data)
            else:
                r = ctx.post(sess, path, data or {})
            body = _body_text(r).lower()
            if (r is not None and r.status_code == 500) and any(s in body for s in _DEBUG_SIGNS):
                return CheckResult(
                    check_id="verbose_errors", category="dynamic", label=label,
                    score=float(cfg.get("score_leaked", 0)), weight=weight, passed=False,
                    penalty_reasons=[f"{method} {path} → 스택트레이스/디버거 노출 (디버그 모드/상세 오류)"],
                    evidence=[_snip(f"{path}: {_body_text(r)}")],
                )
        return CheckResult(
            check_id="verbose_errors", category="dynamic", label=label,
            score=float(cfg.get("score_clean", 100)), weight=weight, passed=True,
            penalty_reasons=[], evidence=[_snip("잘못된 입력에도 스택트레이스/디버거 미노출")],
        )
    except Exception as exc:  # pragma: no cover
        return _scored_zero("verbose_errors", label, weight, f"오류 처리 프로브 예외: {exc}")


CHECKS = [
    Check("verbose_errors", "오류 처리(스택트레이스 노출)", "dynamic", dynamic_verbose_errors),
]
