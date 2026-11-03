"""A07 Authentication Failures: the functional gate (signup/login/create_post,
drives the gate), the weak-password-policy, default-credential and
session-management probes.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional

import requests

from ..models import CheckResult
from ..shared.http import (
    Account, DynamicContext, _body_text, _json_or_none, _login_payload,
    _looks_like_login_form, _post_payload, _signup_payload, _snip,
    admin_access, create_post_id, new_account, record_id,
)
from .base import Check, _undecidable, result


def _once_more(send):
    """Retry a core functional request once when it gets no response: one timeout
    under grading load must not cap the score at the functional-gate limit. A retried
    signup that already landed answers 409, which counts as ok."""
    r = send()
    return r if r is not None else send()


# functional (drives the gate). Opts out of standard handling (standard=False in
# CHECKS): the runner calls it specially with an injected "require" key and reads
# .passed to drive the gate cap, and its exception must PROPAGATE (원칙 5 예외 ①).
def dynamic_functional(ctx: DynamicContext, cfg: Dict[str, Any]) -> CheckResult:
    """signup A/B, login each, A creates a post. Score = pass-rate over the
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

    # Only the two randomized participant accounts. The grader no longer signs up an
    # "admin": apps often pre-seed one, the duplicate signup 409s, and an app whose
    # 409 path leaks an open sqlite write transaction then 500s every later write —
    # a failure the grader itself would cause.
    accounts = [a for a in (ctx.userA, ctx.userB) if a is not None]

    # signup (409 "exists" counts as ok).
    for acct in accounts:
        r = _once_more(lambda: ctx.post(acct.session, "/signup", _signup_payload(acct)))
        if r is None:
            step_ok["signup"] = False
            reasons.append(f"{acct.username} 회원가입 요청 실패(무응답) → 기능 게이트")
        elif r.status_code not in (200, 201, 409):
            step_ok["signup"] = False
            reasons.append(f"{acct.username} 회원가입 실패(HTTP {r.status_code}) → 기능 게이트")
            evidence.append(_snip(f"signup {acct.username} -> {r.status_code}: {_body_text(r)}"))

    # login; capture user id
    for acct in accounts:
        r = _once_more(lambda: ctx.post(acct.session, "/login", _login_payload(acct)))
        if r is None or r.status_code != 200:
            code = "무응답" if r is None else f"HTTP {r.status_code}"
            step_ok["login"] = False
            reasons.append(f"{acct.username} 로그인 실패({code}) → 기능 게이트")
            if r is not None:
                evidence.append(_snip(f"login {acct.username} -> {r.status_code}: {_body_text(r)}"))
            continue
        j = _json_or_none(r)
        if isinstance(j, dict):
            for key in ("id", "uid", "user_id"):
                if record_id(j.get(key)) is not None:
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
        ctrl_sess = requests.Session()
        ctrl = ctx.post(ctrl_sess, "/login", _login_payload(ctx.userA))
        wrong_reachable = wrong is not None and 200 <= wrong.status_code < 400
        wrong_is_form = _looks_like_login_form(_body_text(wrong))
        ctrl_is_form = _looks_like_login_form(_body_text(ctrl))
        accepted = wrong_reachable and not wrong_is_form and not ctrl_is_form
        # Apps that keep one session per user just ended userA's first session with
        # this control login: continue as userA on the control session.
        if ctrl is not None and 200 <= ctrl.status_code < 400 and not ctrl_is_form:
            ctx.userA.session = ctrl_sess
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
        payload = _post_payload("func-check", "hello-" + uuid.uuid4().hex[:8])
        r = _once_more(lambda: ctx.post(ctx.userA.session, "/posts", payload))
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
        label="기능 게이트",
        score=score,
        weight=weight,
        passed=not functional_failed,
        penalty_reasons=reasons if functional_failed else [],
        evidence=evidence,
    )
    return result


# ── weak_password_policy  (dynamic) — signup with a password under 8 chars must fail.
def dynamic_weak_password_policy(check, ctx, cfg):
    """ISMS-P 2.5.4 / KISA / ASVS 6.2.1: signup must refuse a password shorter than 8
    chars. Only length is judged: digits-only or id-like rules differ between standards
    and are not penalized. Acceptance is proven by logging in with the short password."""
    tag = uuid.uuid4().hex[:8]
    uname = f"weakpw{tag}"
    phone = "010" + (tag[:7] + "0").translate(str.maketrans("abcdef", "012345"))
    pw = str(cfg.get("short_password", "Abc12!x"))
    works = _signup_and_login_works(ctx, uname, phone, pw)
    if works is None:
        return _undecidable(check, cfg, "가입·로그인 요청에 응답이 없거나 서버 오류라 판정 불가")
    if not works:
        return result(check, cfg, score=cfg.get("score_enforced", 100), passed=True,
                      evidence=[_snip(f"8자 미만 비밀번호 {pw!r} 가입 거부됨")])
    return result(check, cfg, score=cfg.get("score_weak", 0), passed=False,
                  reasons=[f"8자 미만 비밀번호 {pw!r}로 가입과 로그인 성공"])


def _signup_and_login_works(ctx, uname, phone, pw) -> Optional[bool]:
    # 2xx alone isn't acceptance — form apps re-render the signup form with HTTP 200
    # on a rejected password. Only a reached authenticated state proves acceptance.
    # None: no response or a 5xx, which is neither acceptance nor refusal.
    acct = new_account(ctx, username=uname, phone=phone, name="Weak", password=pw)
    r = acct.signup_response
    if r is None or r.status_code >= 500:
        return None
    if r.status_code not in (200, 201):
        return False
    login = ctx.post(requests.Session(), "/login", _login_payload(acct))
    if login is None or login.status_code >= 500:
        return None
    return 200 <= login.status_code < 400 and not _looks_like_login_form(_body_text(login))


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
        fails.append("로그아웃 후에도 세션이 인증 상태 유지 — 로그아웃 전 쿠키를 재사용하면 그대로 로그인됨(서버측 세션 무효화 없음)")
    ev = [_snip(f"old_password 확인={oldpw}, logout 세션무효화={logout}")]
    if not fails:
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True, evidence=ev)
    score = cfg.get("score_both_broken", 0) if len(fails) == 2 else cfg.get("score_partial", 40)
    return result(check, cfg, score=score, passed=False, reasons=fails, evidence=ev)


def _sm_signup_login(ctx) -> Optional[Account]:
    return new_account(ctx, "sessmgmt", login=True, pw_tag="Sess")


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
    acct = _sm_signup_login(ctx)
    if acct is None:
        return "skip"
    sess, u, p, pw0 = acct.session, acct.username, acct.phone, acct.password
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
    acct = _sm_signup_login(ctx)
    if acct is None:
        return "skip"
    sess, u, p, pw0 = acct.session, acct.username, acct.phone, acct.password
    if not _sm_can_create(ctx, sess):
        return "skip"                       # positive control: authed action must work first
    # Keep a copy of the session cookie as an attacker who stole it would.
    stolen = requests.Session()
    stolen.cookies.update(sess.cookies)
    lo = ctx.post(sess, "/logout", {})
    if lo is None or lo.status_code >= 400:
        return "skip"                       # no working /logout to test invalidation on
    # Still authed after logout is meaningless if /posts is simply anon-open.
    if _sm_can_create(ctx, requests.Session()):
        return "skip"
    if _sm_can_create(ctx, sess):
        return "fail"                       # logout didn't even end the browser's session
    # SW 개발보안 설계 4.1: logout must remove the session completely — a replayed
    # pre-logout cookie must no longer authenticate (Flask's default client-side
    # session stays valid until it expires unless the app revokes it server-side).
    if _sm_can_create(ctx, stolen):
        return "fail"
    return "pass"


# ── session_timeout  (static) — how long a session cookie stays valid.
# Flask verifies EVERY session cookie against PERMANENT_SESSION_LIFETIME (default 31
# days), permanent or not, so an app that never sets it keeps stolen/replayed cookies
# valid for a month. KISA SC: 10분 권고 · SW 개발보안 설계 4.1: 15~30분 · NIST 800-63B-4
# AAL2 idle ≤1h · PCI DSS 8.2.8: 15분 · ASVS 5.0 7.3.1/7.3.2 (L2).
_LIFETIME = re.compile(
    r"""(?:PERMANENT_SESSION_LIFETIME["'\]]*\s*[=:]\s*|permanent_session_lifetime\s*=\s*)"""
    r"""(?P<v>(?:datetime\.)?timedelta\([^)]*\)|\d+)""")
_IDLE_KEY = re.compile(r"""session\s*\[\s*['"](?:last\w*|expires?\w*|idle\w*)['"]\s*\]""", re.IGNORECASE)
_TD_PART = re.compile(r"""(days|hours|minutes|seconds)\s*=\s*(\d+(?:\.\d+)?)""")
_TD_MINUTES = re.compile(r"""timedelta\(\s*minutes\s*=\s*(\d+)""")


def _minutes(expr: str):
    if expr.isdigit():
        return int(expr) / 60.0
    parts = dict((k, float(v)) for k, v in _TD_PART.findall(expr))
    if not parts:
        return None
    return (parts.get("days", 0) * 1440 + parts.get("hours", 0) * 60
            + parts.get("minutes", 0) + parts.get("seconds", 0) / 60.0)


def check_session_timeout(check, sctx, cfg):
    full, part = float(cfg.get("full_minutes", 30)), float(cfg.get("partial_minutes", 60))
    text = "\n".join(src for _p, src in sctx.sources)
    minutes, how = None, ""
    m = _LIFETIME.search(text)
    if m:
        minutes, how = _minutes(m.group("v")), f"PERMANENT_SESSION_LIFETIME = {m.group('v')}"
    elif _IDLE_KEY.search(text):
        td = [int(x) for x in _TD_MINUTES.findall(text)]
        if td:
            minutes, how = float(min(td)), f"세션 마지막 활동 시각 기반 유휴 타임아웃 {min(td)}분"
    if minutes is None:
        return result(check, cfg, score=cfg.get("score_default", 0), passed=False,
                      reasons=["세션 유효시간 미설정 → Flask 기본 31일 동안 세션 쿠키가 유효(유출·재사용 쿠키가 한 달간 통함)"])
    if minutes <= full:
        return result(check, cfg, score=cfg.get("score_full", 100), passed=True, evidence=[_snip(how)])
    if minutes <= part:
        return result(check, cfg, score=cfg.get("score_partial", 50), passed=False,
                      reasons=[f"세션 유효시간 {minutes:g}분 → 권고(30분 이하)보다 김"], evidence=[_snip(how)])
    return result(check, cfg, score=cfg.get("score_default", 0), passed=False,
                  reasons=[f"세션 유효시간 {minutes:g}분 → 60분 초과(KISA·NIST·PCI 권고 초과)"], evidence=[_snip(how)])


# ── default_credentials  (dynamic) — app-seeded admin with a guessable password.
# AI apps habitually seed `admin/admin` (or admin123…) in init_db. Effect-based: a
# guessed login must reach the admin area that an anonymous session can't.
def dynamic_default_credentials(check, ctx, cfg):
    anon_path, answered = admin_access(ctx, requests.Session())
    if anon_path is not None:
        # A login would add nothing an anonymous visitor lacks: access_control_admin
        # judges (and deducts) the open admin area once.
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True, unproven=True,
                      evidence=[_snip(f"로그인 없이도 {anon_path}에 들어감. 감점은 관리자 페이지 접근 통제에서 한 번만")])
    pairs = list(ctx.config.get("probes.default_credentials", []) or [])
    for pair in pairs:
        user, pw = str(pair.get("username", "")), str(pair.get("password", ""))
        sess = requests.Session()
        r = ctx.post(sess, "/login", _login_payload(Account(phone="", password=pw, username=user)))
        if r is None:
            answered = False
            continue
        if not (200 <= r.status_code < 400) or _looks_like_login_form(_body_text(r)):
            continue
        path, ok = admin_access(ctx, sess)
        answered = answered and ok
        if path is not None:
            return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                          reasons=[f"앱이 심어 둔 기본 관리자 계정 {user}/{pw} 로 로그인해 관리자 기능 접근 → 관리자 탈취"],
                          evidence=[_snip(f"POST /login {user}/{pw} -> {r.status_code}; /admin 관리자 화면 접근")])
    if not answered:
        return _undecidable(check, cfg, "로그인·관리자 페이지 요청에 응답이 없어 판정 불가")
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip(f"흔한 기본 관리자 계정 {len(pairs)}종으로 관리자 접근 실패")])


CHECKS = [
    Check("functional", "기능 게이트", "dynamic", dynamic_functional,
          standard=False),
    Check("weak_password_policy", "비밀번호 정책", "dynamic", dynamic_weak_password_policy),
    Check("default_credentials", "기본 관리자 계정", "dynamic", dynamic_default_credentials),
    Check("session_timeout", "Session Timeout", "static", check_session_timeout),
    Check("auth_session_management", "세션 관리", "dynamic",
          dynamic_auth_session_management),
]
