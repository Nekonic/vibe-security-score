"""Dynamic attack probes. Each returns a CheckResult (category="dynamic").

Verdicts come from real HTTP responses only (IDOR / access-control are judged by
RUNTIME cross-account access, never static heuristics). All constants come from
config. Probes share a ProbeContext (one requests.Session per account for cookie
isolation, plus discovered user ids); ``functional`` runs first and drives the gate.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

from ..config import Config
from ..models import CheckResult
from . import sqlmap as sqlmap_tool

_EVIDENCE_MAX = 400


def _snip(text: str, limit: int = _EVIDENCE_MAX) -> str:
    text = text or ""
    if len(text) > limit:
        return text[:limit] + "…(truncated)"
    return text


def _body_text(resp: Optional[requests.Response]) -> str:
    if resp is None:
        return ""
    try:
        return resp.text or ""
    except Exception:
        return ""


def _json_or_none(resp: Optional[requests.Response]) -> Optional[Any]:
    if resp is None:
        return None
    try:
        return resp.json()
    except Exception:
        return None


_LOGIN_FORM_MARKERS = ('type="password"', "type='password'", "type=password",
                       'name="password"', "name='password'")


def _looks_like_login_form(text: str) -> bool:
    # Form apps re-render the login page with HTTP 200 on a failed login, so
    # status alone can't tell acceptance from rejection — a password input means
    # the user was NOT logged in.
    t = (text or "").lower()
    return any(m in t for m in _LOGIN_FORM_MARKERS)


@dataclass
class Account:
    email: str
    password: str
    name: str = ""
    session: requests.Session = field(default_factory=requests.Session)
    user_id: Optional[int] = None
    is_admin: bool = False


class ProbeContext:
    def __init__(self, base_url: str, config: Config):
        self.base_url = base_url.rstrip("/")
        self.config = config
        self.http_timeout = float(config.get("timeouts.http_request", 8))

        probes = config.get("probes", {}) or {}
        accts = probes.get("test_accounts", []) or []
        self.userA = Account(**{k: accts[0][k] for k in ("email", "password", "name") if k in accts[0]}) if accts else None
        self.userB = Account(**{k: accts[1][k] for k in ("email", "password", "name") if k in accts[1]}) if len(accts) > 1 else None
        adm = probes.get("admin_account", {}) or {}
        self.admin = Account(email=adm.get("email", ""), password=adm.get("password", ""), name=adm.get("name", "Admin"))
        self.admin.is_admin = True

        self.xss_payload = str(probes.get("xss_payload", "<script>alert('xss-{marker}')</script>"))
        self.sqli_payloads = list(probes.get("sqli_payloads", []) or [])
        self.sqlmap_cfg = dict(config.get("tools.sqlmap", {}) or {})

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, sess: requests.Session, path: str, **kw) -> Optional[requests.Response]:
        try:
            return sess.get(self._url(path), timeout=self.http_timeout, **kw)
        except requests.RequestException:
            return None

    def post(self, sess: requests.Session, path: str, data: Dict[str, Any]) -> Optional[requests.Response]:
        """POST leniently: try JSON, fall back to form if the app 4xx-rejects it."""
        try:
            r = sess.post(self._url(path), json=data, timeout=self.http_timeout)
        except requests.RequestException:
            return None
        if r is not None and r.status_code in (400, 415, 422):
            try:
                r2 = sess.post(self._url(path), data=data, timeout=self.http_timeout)
                if r2 is not None and r2.status_code < r.status_code:
                    return r2
            except requests.RequestException:
                pass
        return r


# Probe 1: functional (drives the gate)
def probe_functional(ctx: ProbeContext, cfg: Dict[str, Any], require: List[str]):
    """signup A/B/admin, login each, A creates a post. Returns (CheckResult,
    functional_failed). Score = pass-rate over the ``require`` gate steps."""
    weight = float(cfg.get("weight", 10))
    step_ok: Dict[str, bool] = {
        "signup": True, "login": True, "create_post": False,
        "wrong_password_rejected": True,
    }
    reasons: List[str] = []
    evidence: List[str] = []

    accounts = [a for a in (ctx.userA, ctx.userB, ctx.admin) if a is not None]

    # signup all accounts (409 "exists" counts as ok)
    for acct in accounts:
        r = ctx.post(acct.session, "/signup", {"email": acct.email, "name": acct.name, "password": acct.password})
        if r is None:
            step_ok["signup"] = False
            reasons.append(f"{acct.email} 회원가입 요청 실패(무응답) → 기능 게이트")
        elif r.status_code in (200, 201, 409):
            pass
        else:
            step_ok["signup"] = False
            reasons.append(f"{acct.email} 회원가입 실패(HTTP {r.status_code}) → 기능 게이트")
            evidence.append(_snip(f"signup {acct.email} -> {r.status_code}: {_body_text(r)}"))

    # login all accounts; capture user id
    for acct in accounts:
        r = ctx.post(acct.session, "/login", {"email": acct.email, "password": acct.password})
        if r is None or r.status_code != 200:
            step_ok["login"] = False
            code = "무응답" if r is None else f"HTTP {r.status_code}"
            reasons.append(f"{acct.email} 로그인 실패({code}) → 기능 게이트")
            if r is not None:
                evidence.append(_snip(f"login {acct.email} -> {r.status_code}: {_body_text(r)}"))
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
            {"email": ctx.userA.email, "password": ctx.userA.password + "-WRONG-" + uuid.uuid4().hex[:6]},
        )
        ctrl = ctx.post(
            requests.Session(), "/login",
            {"email": ctx.userA.email, "password": ctx.userA.password},
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
        r = ctx.post(ctx.userA.session, "/posts", {"title": "func-check", "body": "hello-" + uuid.uuid4().hex[:8]})
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
    return result, functional_failed


# Probe 2: idor_profile
def _discover_user_id(ctx: ProbeContext, acct: Account) -> Optional[int]:
    """If login didn't return an id, probe /users/<n> with the account's own
    session and match its email to find its id."""
    if acct is None:
        return None
    for uid in range(1, 11):
        r = ctx.get(acct.session, f"/users/{uid}")
        if r is None or r.status_code != 200:
            continue
        body = _body_text(r)
        if acct.email and acct.email in body:
            return uid
    return None


def probe_idor_profile(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 18))
    label = "IDOR(타인 프로필 조회)"
    try:
        if ctx.userA is None or ctx.userB is None:
            return _low_conf("idor_profile", label, weight, "테스트 계정 구성 부족으로 IDOR 판정 불가")

        if ctx.userA.user_id is None:
            ctx.userA.user_id = _discover_user_id(ctx, ctx.userA)
        if ctx.userA.user_id is None:
            return _low_conf("idor_profile", label, weight,
                             "userA의 id를 확인할 수 없어 IDOR 판정 불가", passed=False)

        target = f"/users/{ctx.userA.user_id}"

        # Secondary signal: are user ids sequential predictable integers?
        observed_ids = sorted(
            a.user_id for a in (ctx.userA, ctx.userB, ctx.admin)
            if a is not None and isinstance(a.user_id, int)
        )
        predictable = (
            len(observed_ids) >= 2
            and all(b - a == 1 for a, b in zip(observed_ids, observed_ids[1:]))
        )
        predictable_penalty = float(cfg.get("predictable_id_penalty", 0))

        # Control: userA sees own email on own profile.
        ctrl = ctx.get(ctx.userA.session, target)
        ctrl_body = _body_text(ctrl)
        control_ok = ctrl is not None and ctrl.status_code == 200 and ctx.userA.email in ctrl_body

        # Attack: userB reads userA's profile.
        atk = ctx.get(ctx.userB.session, target)
        atk_body = _body_text(atk)
        atk_code = atk.status_code if atk is not None else None
        leaked = atk is not None and atk.status_code == 200 and ctx.userA.email in atk_body

        evidence = [_snip(f"userA self {target} -> {ctrl.status_code if ctrl else 'n/a'}: {ctrl_body}"),
                    _snip(f"userB attack {target} -> {atk_code}: {atk_body}")]

        if leaked:
            reasons = [f"userB 세션으로 userA({ctx.userA.email}) 이메일 조회됨 → IDOR"]
            if predictable:
                reasons.append("순차 정수 id 노출로 예측 가능 (참고)")
            return CheckResult(
                check_id="idor_profile", category="dynamic", label=label,
                score=float(cfg.get("score_leaked", 0)), weight=weight, passed=False,
                penalty_reasons=reasons,
                evidence=evidence,
            )
        if not control_ok:
            return CheckResult(
                check_id="idor_profile", category="dynamic", label=label,
                score=float(cfg.get("score_control_broken", 60)), weight=weight, passed=False,
                penalty_reasons=["본인 이메일도 조회되지 않아 접근 통제 확인 불가(control broken)"],
                evidence=evidence,
            )
        # Defended: masked / 403 / 404 for the attacker; apply the small
        # predictable-id deduction here only (never rescues a leaked verdict).
        defended = float(cfg.get("score_defended", 100))
        def_reasons: List[str] = []
        def_evidence = [_snip(f"userB attack {target} -> {atk_code} (이메일 미노출/차단)")]
        if predictable and predictable_penalty > 0:
            defended = max(0.0, defended - predictable_penalty)
            def_reasons.append(
                f"순차 정수 id 노출로 예측 가능 (소액 감점 -{predictable_penalty:g}); ids={observed_ids}"
            )
        return CheckResult(
            check_id="idor_profile", category="dynamic", label=label,
            score=defended, weight=weight, passed=True,
            penalty_reasons=def_reasons,
            evidence=def_evidence,
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("idor_profile", label, weight, f"IDOR 프로브 예외: {exc}")


# Probe 3: access_control_admin
_ADMIN_MARKERS = ("admin dashboard", "운영자", "사용자 목록", "admin users", "is_admin")


def _looks_like_admin(body: str, j: Any) -> bool:
    low = (body or "").lower()
    if any(m.lower() in low for m in _ADMIN_MARKERS):
        return True
    if isinstance(j, dict) and isinstance(j.get("users"), list) and j["users"]:
        return True
    return False


def probe_access_control_admin(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 18))
    label = "접근 통제(관리자 페이지)"
    try:
        if ctx.userB is None:
            return _low_conf("access_control_admin", label, weight, "일반 사용자 세션 없음으로 판정 불가")

        exposed_paths: List[str] = []
        codes: Dict[str, Optional[int]] = {}
        evidence: List[str] = []

        for path in ("/admin", "/admin/users"):
            r = ctx.get(ctx.userB.session, path)
            code = r.status_code if r is not None else None
            codes[path] = code
            body = _body_text(r)
            j = _json_or_none(r)
            if code == 200 and _looks_like_admin(body, j):
                exposed_paths.append(path)
            evidence.append(_snip(f"userB GET {path} -> {code}: {body}"))

        # Control: admin account must still reach admin (if required).
        admin_control_ok = True
        require_admin = bool(cfg.get("require_admin_control", True))
        if require_admin and ctx.admin is not None:
            ra = ctx.get(ctx.admin.session, "/admin")
            ru = ctx.get(ctx.admin.session, "/admin/users")
            admin_control_ok = any(
                r is not None and r.status_code == 200 and _looks_like_admin(_body_text(r), _json_or_none(r))
                for r in (ra, ru)
            )

        if exposed_paths:
            reasons = [f"일반 사용자(userB) 세션으로 {p} 노출됨 → 접근 통제 실패" for p in exposed_paths]
            return CheckResult(
                check_id="access_control_admin", category="dynamic", label=label,
                score=float(cfg.get("score_exposed", 0)), weight=weight, passed=False,
                penalty_reasons=reasons, evidence=evidence,
            )

        # All blocked. Award 404 concealment only if admin control still works.
        both_404 = all(codes.get(p) == 404 for p in ("/admin", "/admin/users"))
        if both_404:
            if require_admin and not admin_control_ok:
                return CheckResult(
                    check_id="access_control_admin", category="dynamic", label=label,
                    score=float(cfg.get("score_403", 90)), weight=weight, passed=True,
                    penalty_reasons=["관리자 페이지가 관리자 계정에서도 도달 불가 — 은닉 보너스는 유보"],
                    evidence=evidence,
                )
            return CheckResult(
                check_id="access_control_admin", category="dynamic", label=label,
                score=float(cfg.get("score_404", 100)), weight=weight, passed=True,
                penalty_reasons=[], evidence=evidence,
            )

        # Blocked (403/redirect/other non-exposing) => defended.
        return CheckResult(
            check_id="access_control_admin", category="dynamic", label=label,
            score=float(cfg.get("score_403", 90)), weight=weight, passed=True,
            penalty_reasons=[], evidence=evidence,
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("access_control_admin", label, weight, f"접근 통제 프로브 예외: {exc}")


# Probe 4: stored_xss
def probe_stored_xss(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 18))
    label = "저장형 XSS"
    try:
        if ctx.userA is None:
            return _low_conf("stored_xss", label, weight, "작성자 세션 없음으로 XSS 판정 불가")

        marker = uuid.uuid4().hex[:10]
        payload = ctx.xss_payload.replace("{marker}", marker)
        raw_signature = payload  # if it appears verbatim in output it was NOT escaped

        rejected = True  # becomes False if any sink accepted our input
        evidence: List[str] = []
        sess = ctx.userA.session

        # Sink 1: post body.
        rp = ctx.post(sess, "/posts", {"title": f"xss-{marker}", "body": payload})
        if rp is not None and rp.status_code in (200, 201):
            rejected = False

        # Sink 2: profile name/email (best-effort; may be optional).
        if ctx.userA.user_id is not None:
            for path in (f"/users/{ctx.userA.user_id}", "/profile"):
                try:
                    ru = sess.post(ctx._url(path), json={"name": payload}, timeout=ctx.http_timeout)
                    if ru is not None and ru.status_code in (200, 201):
                        rejected = False
                except requests.RequestException:
                    pass

        # Render check: fetch /posts and the profile; look for the RAW payload.
        unescaped = False
        rendered = ctx.get(sess, "/posts")
        rbody = _body_text(rendered)
        if raw_signature in rbody:
            unescaped = True
            evidence.append(_snip(f"/posts 렌더에 원본 <script> 노출: …{_snip(rbody[max(0, rbody.find(raw_signature) - 40): rbody.find(raw_signature) + 80], 160)}"))

        if not unescaped and ctx.userA.user_id is not None:
            prof = ctx.get(sess, f"/users/{ctx.userA.user_id}")
            pbody = _body_text(prof)
            if raw_signature in pbody:
                unescaped = True
                evidence.append(_snip(f"프로필 렌더에 원본 <script> 노출: {pbody}"))

        if unescaped:
            return CheckResult(
                check_id="stored_xss", category="dynamic", label=label,
                score=float(cfg.get("score_stored_unescaped", 0)), weight=weight, passed=False,
                penalty_reasons=[f"게시글/프로필에 <script> 페이로드가 이스케이프 없이 렌더됨 → 저장형 XSS (marker={marker})"],
                evidence=evidence,
            )

        note = "입력이 거부되어 저장 안됨" if rejected else "저장되었으나 출력 시 이스케이프됨"
        return CheckResult(
            check_id="stored_xss", category="dynamic", label=label,
            score=float(cfg.get("score_escaped_or_rejected", 100)), weight=weight, passed=True,
            penalty_reasons=[], evidence=[_snip(f"XSS 방어됨 ({note}); marker={marker}")],
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("stored_xss", label, weight, f"XSS 프로브 예외: {exc}")


# Probe 5: sqli
def _row_count(resp: Optional[requests.Response]) -> Optional[int]:
    """Best-effort count of returned rows from JSON."""
    j = _json_or_none(resp)
    if isinstance(j, list):
        return len(j)
    if isinstance(j, dict):
        for key in ("results", "posts", "users", "data", "rows"):
            if isinstance(j.get(key), list):
                return len(j[key])
    return None


_SQL_ERROR_SIGNS = (
    "sqlite3", "operationalerror", "no such column", "syntax error",
    "sql error", "unrecognized token", "programmingerror", "psycopg2",
    "you have an error in your sql", "traceback (most recent call last)",
)


def _has_sql_error(resp: Optional[requests.Response]) -> bool:
    if resp is None:
        return False
    if resp.status_code == 500:
        return True
    low = _body_text(resp).lower()
    return any(sign in low for sign in _SQL_ERROR_SIGNS)


_SQLI_LABEL = "SQL 인젝션(/search, /posts sort)"


def probe_sqli(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    """SQLi verdict: sqlmap PRIMARY (if enabled+installed), built-in oracle FALLBACK."""
    weight = float(cfg.get("weight", 16))
    label = _SQLI_LABEL

    try:
        outcome = sqlmap_tool.run_sqlmap(ctx.base_url, ctx.sqlmap_cfg)
    except Exception as exc:  # any surprise => fall back
        outcome = sqlmap_tool.SqlmapOutcome(ran=False, reason=f"sqlmap 래퍼 예외({exc}) → 폴백")

    if outcome.ran and outcome.injectable:
        ev = ["path=sqlmap (primary)"] + [_snip(e) for e in outcome.evidence]
        return CheckResult(
            check_id="sqli", category="dynamic", label=label,
            score=float(cfg.get("score_injection", 0)), weight=weight, passed=False,
            penalty_reasons=["sqlmap이 /search 또는 /posts 파라미터에서 SQL 인젝션 확인 → 매개변수 바인딩 미적용"],
            evidence=ev, tool="sqlmap",
        )

    fallback_note = outcome.reason or "내장 오라클 사용"
    return _sqli_builtin_oracle(ctx, cfg, weight, label, fallback_note)


def _sqli_builtin_oracle(
    ctx: ProbeContext, cfg: Dict[str, Any], weight: float, label: str, fallback_note: str
) -> CheckResult:
    try:
        sess = ctx.userA.session if ctx.userA is not None else requests.Session()
        evidence: List[str] = [_snip(f"path=requests-oracle (fallback: {fallback_note})")]
        injection = False
        error_leak = False

        # Boolean differential on /search?q=
        marker = uuid.uuid4().hex[:8]
        if ctx.userA is not None:
            ctx.post(sess, "/posts", {"title": f"sqli-seed-{marker}", "body": "seed"})

        benign = ctx.get(sess, "/search", params={"q": f"nomatch-{uuid.uuid4().hex}"})
        benign_n = _row_count(benign)
        inj = ctx.get(sess, "/search", params={"q": "%' OR '1'='1"})
        inj_n = _row_count(inj)

        if benign_n is not None and inj_n is not None and inj_n > benign_n and inj_n > 0:
            injection = True
            evidence.append(_snip(f"/search boolean 차등: benign={benign_n} rows vs \"OR 1=1\"={inj_n} rows → SQLi"))

        if not injection:
            for pay in ctx.sqli_payloads:
                r = ctx.get(sess, "/search", params={"q": pay})
                n = _row_count(r)
                if n is not None and benign_n is not None and n > benign_n and n > 0:
                    injection = True
                    evidence.append(_snip(f"/search payload {pay!r} → {n} rows(>{benign_n}) → SQLi"))
                    break
                if _has_sql_error(r):
                    error_leak = True
                    evidence.append(_snip(f"/search payload {pay!r} → SQL 오류 노출: {_body_text(r)}"))

        # Error-based on /posts?sort= (nonexistent column)
        bad_sort = ctx.get(sess, "/posts", params={"sort": "no_such_col_" + uuid.uuid4().hex[:6]})
        if _has_sql_error(bad_sort):
            error_leak = True
            evidence.append(_snip(f"/posts?sort=<bad col> → HTTP {bad_sort.status_code if bad_sort else 'n/a'} / SQL 오류"))
        # Comment-injected sort returning 200 while a bad column 500s => raw interpolation.
        inj_sort = ctx.get(sess, "/posts", params={"sort": "id-- "})
        if inj_sort is not None and bad_sort is not None:
            if inj_sort.status_code == 200 and bad_sort.status_code == 500:
                injection = True
                evidence.append(_snip("/posts?sort= 원본 문자열 보간 확인(주석 주입 200 / 잘못된 컬럼 500) → SQLi"))

        if injection:
            return CheckResult(
                check_id="sqli", category="dynamic", label=label,
                score=float(cfg.get("score_injection", 0)), weight=weight, passed=False,
                penalty_reasons=["/search 또는 /posts?sort= 에서 SQL 인젝션 성공 → 매개변수 바인딩 미적용"],
                evidence=evidence,
            )
        if error_leak:
            return CheckResult(
                check_id="sqli", category="dynamic", label=label,
                score=float(cfg.get("score_error_leak", 40)), weight=weight, passed=False,
                penalty_reasons=["완전한 인젝션은 아니나 SQL 오류/스택트레이스가 응답에 노출됨"],
                evidence=evidence,
            )
        return CheckResult(
            check_id="sqli", category="dynamic", label=label,
            score=float(cfg.get("score_no_injection", 100)), weight=weight, passed=True,
            penalty_reasons=[], evidence=[_snip("boolean 차등/오류 노출 모두 없음 → 인젝션 미발견")],
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("sqli", label, weight, f"SQLi 프로브 예외: {exc}")


def _low_conf(check_id: str, label: str, weight: float, reason: str, passed: bool = False) -> CheckResult:
    """A check we could NOT reliably test. Marked ``skipped`` so aggregation
    EXCLUDES it — scoring an untestable check as vulnerable would falsely penalize
    a defended app. Still reported so the operator sees why it was skipped."""
    return CheckResult(
        check_id=check_id,
        category="dynamic",
        label=label,
        score=0.0,
        weight=weight,
        passed=passed,
        skipped=True,
        penalty_reasons=[f"검사 생략(판정 불가): {reason}"],
        evidence=[],
    )
