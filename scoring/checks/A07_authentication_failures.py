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
    _post_payload, _signup_payload, _snip, create_post_id,
)
from .base import Check, _undecidable, result


# functional (drives the gate). Opts out of standard handling (standard=False in
# CHECKS): the runner calls it specially with an injected "require" key and reads
# .passed to drive the gate cap, and its exception must PROPAGATE (원칙 5 예외 ①).
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
            reasons.append(f"{ctx.userA.username}: 틀린 비밀번호가 수락됨 → 인증 취약")
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


# ── weak_password_policy  (dynamic) — signup with a trivial password must fail.
def dynamic_weak_password_policy(check, ctx, cfg):
    weak = str(cfg.get("weak_password", "123"))
    tag = uuid.uuid4().hex[:8]
    uname, phone = f"weakpw-{tag}", "010" + tag[:8].translate(str.maketrans("abcdef", "012345"))
    r = ctx.post(requests.Session(), "/signup",
                 {"username": uname, "phone": phone, "name": "Weak", "password": weak})
    # 2xx alone isn't acceptance — form apps re-render the signup form with HTTP 200
    # on a rejected password. Confirm the weak account was really created by logging
    # in with it; only a reached authenticated state proves no policy.
    accepted = False
    if r is not None and r.status_code in (200, 201):
        login = ctx.post(requests.Session(), "/login",
                         {"username": uname, "phone": phone, "password": weak})
        accepted = (
            login is not None and 200 <= login.status_code < 400
            and not _looks_like_login_form(_body_text(login))
        )
    if accepted:
        return result(check, cfg, score=cfg.get("score_weak", 0), passed=False,
                      reasons=[f"취약한 비밀번호({weak!r})로 가입·로그인 성공 → 비밀번호 정책 없음"],
                      evidence=[_snip(f"signup weak-pw -> {r.status_code}, 이후 로그인 성공")])
    code = "무응답" if r is None else f"HTTP {r.status_code}"
    return result(check, cfg, score=cfg.get("score_enforced", 100), passed=True,
                  evidence=[_snip(f"취약한 비밀번호 거부됨(가입 실패/로그인 불가, signup {code})")])


# ── auth_session_management  (dynamic) — §4.5: two independent auth-lifecycle
# controls, each on its OWN throwaway account so no other probe's session is
# disturbed. (1) POST /account/password must verify the OLD password. (2) POST
# /logout must invalidate the session. Positive control first (§0-3): a control we
# cannot establish downgrades that half to skip — never accuse.
def dynamic_auth_session_management(check, ctx, cfg):
    oldpw = _probe_old_password_check(ctx)
    logout = _probe_logout_invalidation(ctx)
    if oldpw == "skip" and logout == "skip":
        return _undecidable(check, cfg,
                            "비번변경·로그아웃 정상 경로를 세우지 못해 세션관리 판정 불가")
    fails: List[str] = []
    if oldpw == "fail":
        fails.append("비밀번호 변경이 기존 비번을 확인하지 않음(틀린 old_password로도 변경됨)")
    if logout == "fail":
        fails.append("로그아웃 후에도 같은 세션이 인증 상태 유지(세션 무효화 실패)")
    ev = [_snip(f"old_password 확인={oldpw}, logout 세션무효화={logout}")]
    if not fails:
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True, evidence=ev)
    score = cfg.get("score_both_broken", 0) if len(fails) == 2 else cfg.get("score_partial", 40)
    return result(check, cfg, score=score, passed=False, reasons=fails, evidence=ev)


def _sm_account():
    tag = uuid.uuid4().hex[:10]
    return (f"sessmgmt-{tag}",
            "010" + tag[:8].translate(str.maketrans("abcdef", "012345")),
            "SessBase!" + tag[:5])


def _sm_signup_login(ctx, sess, uname, phone, pw) -> bool:
    su = ctx.post(sess, "/signup",
                  {"username": uname, "phone": phone, "name": uname, "password": pw})
    if su is None or su.status_code not in (200, 201, 409):
        return False
    ctx.post(sess, "/login", {"username": uname, "phone": phone, "password": pw})
    return True


def _sm_login_ok(ctx, uname, phone, pw) -> bool:
    """True iff (uname/phone, pw) reaches an authenticated state on a fresh session."""
    r = ctx.post(requests.Session(), "/login",
                 {"username": uname, "phone": phone, "password": pw})
    return (r is not None and 200 <= r.status_code < 400
            and not _looks_like_login_form(_body_text(r)))


def _sm_can_create(ctx, sess) -> bool:
    """Effect-based auth oracle: prove that a post was actually created.

    A generated app may return ``200 {"error": "login required"}`` for an
    unauthorized JSON request. Status/login-form checks alone would misread that as
    a successful write and turn a valid logout into ``skip``. ``create_post_id``
    requires an id or verifies the unique marker in the resulting listing/detail.
    """
    tag = uuid.uuid4().hex[:8]
    return create_post_id(ctx, sess, "sm-" + tag, "b-" + tag) is not None


def _probe_old_password_check(ctx) -> str:
    sess = requests.Session()
    u, p, pw0 = _sm_account()
    if not _sm_signup_login(ctx, sess, u, p, pw0):
        return "skip"
    # Attempt a change with a WRONG old_password. If the new password then logs in,
    # the change was accepted without verifying the old one.
    bad_new = "Bad!" + uuid.uuid4().hex[:8]
    ctx.post(sess, "/account/password",
             {"old_password": "WRONG-" + uuid.uuid4().hex[:6], "new_password": bad_new})
    if _sm_login_ok(ctx, u, p, bad_new):
        return "fail"
    # Positive control: a legit change (correct old_password) MUST work, else we
    # can't prove the endpoint even functions -> skip (don't credit, don't accuse).
    good_new = "Good!" + uuid.uuid4().hex[:8]
    ctx.post(sess, "/account/password", {"old_password": pw0, "new_password": good_new})
    return "pass" if _sm_login_ok(ctx, u, p, good_new) else "skip"


def _probe_logout_invalidation(ctx) -> str:
    sess = requests.Session()
    u, p, pw0 = _sm_account()
    if not _sm_signup_login(ctx, sess, u, p, pw0):
        return "skip"
    if not _sm_can_create(ctx, sess):
        return "skip"                       # positive control: authed action must work first
    lo = ctx.post(sess, "/logout", {})
    if lo is None or lo.status_code >= 400:
        return "skip"                       # no working /logout to test invalidation on
    if not _sm_can_create(ctx, sess):
        return "pass"                       # session killed by logout
    # Still authed after logout — unless /posts is simply anon-open (oracle invalid).
    if _sm_can_create(ctx, requests.Session()):
        return "skip"
    return "fail"


CHECKS = [
    Check("functional", "기능 게이트(회원가입/로그인/글작성)", "dynamic", dynamic_functional,
          standard=False),
    Check("weak_password_policy", "비밀번호 정책", "dynamic", dynamic_weak_password_policy),
    Check("auth_session_management", "인증 세션 관리(비번변경·로그아웃)", "dynamic",
          dynamic_auth_session_management),
]
