"""A07 Authentication Failures: the functional gate (signup/login/create_post,
drives the gate) and the weak-password-policy probe.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List

import requests

from ..models import CheckResult
from ..shared.http import (
    DynamicContext, _body_text, _json_or_none, _login_payload, _looks_like_login_form,
    _scored_zero, _post_payload, _signup_payload, _snip,
)
from .base import Check


# functional (drives the gate)
def dynamic_functional(ctx: DynamicContext, cfg: Dict[str, Any]) -> CheckResult:
    """signup A/B/admin, login each, A creates a post. Score = pass-rate over the
    ``require`` gate steps (in cfg); ``passed`` is the gate verdict the runner caps
    the final score on."""
    weight = float(cfg.get("weight", 10))
    require = list(cfg.get("require") or ["signup", "login", "create_post"])
    step_ok: Dict[str, bool] = {
        "signup": True, "login": True, "create_post": False,
        "wrong_password_rejected": True,
    }
    reasons: List[str] = []
    evidence: List[str] = []

    accounts = [a for a in (ctx.userA, ctx.userB, ctx.admin) if a is not None]

    # signup all accounts (409 "exists" counts as ok). Admin is best-effort: many
    # apps pre-seed an admin with unknown creds, so admin auth must NOT fail the
    # participant functional gate (access-control test handles admin separately).
    for acct in accounts:
        r = ctx.post(acct.session, "/signup", _signup_payload(acct))
        gate = not acct.is_admin
        if r is None:
            if gate:
                step_ok["signup"] = False
                reasons.append(f"{acct.username} 회원가입 요청 실패(무응답) → 기능 게이트")
        elif r.status_code in (200, 201, 409):
            pass
        elif gate:
            step_ok["signup"] = False
            reasons.append(f"{acct.username} 회원가입 실패(HTTP {r.status_code}) → 기능 게이트")
            evidence.append(_snip(f"signup {acct.username} -> {r.status_code}: {_body_text(r)}"))

    # login all accounts; capture user id (admin best-effort, see above)
    for acct in accounts:
        r = ctx.post(acct.session, "/login", _login_payload(acct))
        if r is None or r.status_code != 200:
            code = "무응답" if r is None else f"HTTP {r.status_code}"
            if not acct.is_admin:
                step_ok["login"] = False
                reasons.append(f"{acct.username} 로그인 실패({code}) → 기능 게이트")
            if r is not None:
                evidence.append(_snip(f"login {acct.username} -> {r.status_code}: {_body_text(r)}"))
            continue
        j = _json_or_none(r)
        if isinstance(j, dict):
            for key in ("id", "uid", "user_id"):
                if isinstance(j.get(key), int):
                    acct.user_id = j[key]
                    break

    # broken-auth: a WRONG password for userA must be REJECTED. Judge by whether
    # the wrong-pw attempt reached an authenticated state (no login form), NOT by
    # status code — form apps re-render the login form on failure. Only flag if
    # the wrong-pw response looks like success while the correct-pw control also
    # does. Use throwaway sessions so a wrongly-accepted login can't taint userA.
    if ctx.userA is not None:
        wrong = ctx.post(
            requests.Session(), "/login",
            _login_payload(ctx.userA, ctx.userA.password + "-WRONG-" + uuid.uuid4().hex[:6]),
        )
        ctrl = ctx.post(
            requests.Session(), "/login",
            _login_payload(ctx.userA),
        )
        wrong_reachable = wrong is not None and 200 <= wrong.status_code < 400
        wrong_is_form = _looks_like_login_form(_body_text(wrong))
        ctrl_is_form = _looks_like_login_form(_body_text(ctrl))
        accepted = wrong_reachable and not wrong_is_form and not ctrl_is_form
        if accepted:
            step_ok["wrong_password_rejected"] = False
            reasons.append(f"{ctx.userA.email}: 틀린 비밀번호가 수락됨 → 인증 취약")
            evidence.append(_snip(f"wrong-pw login -> {wrong.status_code} (성공 페이지 반환): {_body_text(wrong)}"))
        else:
            evidence.append(_snip(
                f"wrong-pw 거부 확인 (status={getattr(wrong, 'status_code', None)}, "
                f"로그인폼 재노출={wrong_is_form})"
            ))

    # userA creates a post
    if ctx.userA is not None:
        r = ctx.post(ctx.userA.session, "/posts", _post_payload("func-check", "hello-" + uuid.uuid4().hex[:8]))
        if r is not None and r.status_code in (200, 201):
            step_ok["create_post"] = True
        else:
            code = "무응답" if r is None else f"HTTP {r.status_code}"
            reasons.append(f"userA 게시글 작성 실패({code}) → 기능 게이트")
            if r is not None:
                evidence.append(_snip(f"create_post -> {r.status_code}: {_body_text(r)}"))

    # score = pass-rate over the core required steps + wrong-password guard
    required = [s for s in require if s in step_ok]
    if not required:
        required = [s for s in step_ok if s != "wrong_password_rejected"]
    scored_steps = required + ["wrong_password_rejected"]
    passed_count = sum(1 for s in scored_steps if step_ok.get(s))
    total = len(scored_steps)
    score = float(cfg.get("score_all_pass", 100)) * (passed_count / total) if total else 0.0
    functional_failed = any(not step_ok.get(s) for s in scored_steps)

    result = CheckResult(
        check_id="functional",
        category="dynamic",
        label="기능 게이트(회원가입/로그인/글작성)",
        score=score,
        weight=weight,
        passed=not functional_failed,
        penalty_reasons=reasons if functional_failed else [],
        evidence=evidence,
    )
    return result


# weak_password_policy — signup with a trivial password must fail.
def dynamic_weak_password_policy(ctx: DynamicContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 8))
    label = "비밀번호 정책"
    try:
        weak = str(cfg.get("weak_password", "123"))
        tag = uuid.uuid4().hex[:8]
        r = ctx.post(requests.Session(), "/signup",
                     {"username": f"weakpw-{tag}", "email": f"weakpw-{tag}@test.com",
                      "name": "Weak", "password": weak})
        if r is not None and r.status_code in (200, 201):
            return CheckResult(
                check_id="weak_password_policy", category="dynamic", label=label,
                score=float(cfg.get("score_weak", 0)), weight=weight, passed=False,
                penalty_reasons=[f"취약한 비밀번호({weak!r})로 회원가입 성공 → 비밀번호 정책 없음"],
                evidence=[_snip(f"signup weak-pw -> {r.status_code}")],
            )
        code = "무응답" if r is None else f"HTTP {r.status_code}"
        return CheckResult(
            check_id="weak_password_policy", category="dynamic", label=label,
            score=float(cfg.get("score_enforced", 100)), weight=weight, passed=True,
            penalty_reasons=[], evidence=[_snip(f"취약한 비밀번호 거부됨 ({code})")],
        )
    except Exception as exc:  # pragma: no cover
        return _scored_zero("weak_password_policy", label, weight, f"비밀번호 정책 프로브 예외: {exc}")


CHECKS = [
    Check("functional", "기능 게이트(회원가입/로그인/글작성)", "dynamic", dynamic_functional),
    Check("weak_password_policy", "비밀번호 정책", "dynamic", dynamic_weak_password_policy),
]
