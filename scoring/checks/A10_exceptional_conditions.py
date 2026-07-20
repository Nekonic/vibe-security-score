"""A10 Mishandling of Exceptional Conditions: malformed input must not leak stack
traces / the debugger (dynamic probe).
"""
from __future__ import annotations

import uuid

import requests

from ..shared.http import DynamicContext, _body_text, _snip
from .base import Check, result


# ── verbose_errors  (dynamic) ──────────────────────────────────────────────
_DEBUG_SIGNS = (
    "traceback (most recent call last)", "werkzeug debugger", "werkzeug.debug",
    "/__debugger__", "this is the werkzeug", "sqlalchemy", "file \"/app",
)


def dynamic_verbose_errors(check: Check, ctx: DynamicContext, cfg: dict):
    sess = ctx.userA.session if ctx.userA is not None else requests.Session()
    for method, path, data in _malformed_requests():
        resp = ctx.get(sess, path, params=data) if method == "GET" else ctx.post(sess, path, data or {})
        if _leaks_trace(resp):
            return result(check, cfg, score=cfg.get("score_leaked", 0), passed=False,
                          reasons=[f"{method} {path} → 스택트레이스/디버거 노출 (디버그 모드/상세 오류)"],
                          evidence=[_snip(f"{path}: {_body_text(resp)}")])
    return result(check, cfg, score=cfg.get("score_clean", 100), passed=True,
                  evidence=[_snip("잘못된 입력에도 스택트레이스/디버거 미노출")])


def _malformed_requests():
    return [
        ("GET", "/users/999999999", None),
        ("GET", "/posts", {"sort": "no_such_col_" + uuid.uuid4().hex[:6]}),
        ("POST", "/posts", {"title": None}),
        ("GET", "/search", {"q": "%' "}),
    ]


def _leaks_trace(resp) -> bool:
    if resp is None or resp.status_code != 500:
        return False
    body = _body_text(resp).lower()
    return any(sign in body for sign in _DEBUG_SIGNS)


CHECKS = [
    Check("verbose_errors", "오류 처리(스택트레이스 노출)", "dynamic",
          dynamic_verbose_errors),
]
