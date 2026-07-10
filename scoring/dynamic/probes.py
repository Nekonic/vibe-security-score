"""Dynamic attack probes. Each returns a CheckResult (category="dynamic").

Verdicts come from real HTTP responses only (IDOR / access-control are judged by
RUNTIME cross-account access, never static heuristics). All constants come from
config. Probes share a ProbeContext (one requests.Session per account for cookie
isolation, plus discovered user ids); ``functional`` runs first and drives the gate.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

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


# --- CSRF awareness -------------------------------------------------------
# A correctly CSRF-protected app rejects token-less POSTs (that defense is
# rewarded by the static `csrf_protection` check). The functional/attack probes
# must still be able to act as a legit logged-in user, so they discover the
# session's CSRF token (from a login JSON response, a hidden form field, or a
# <meta> tag) and attach it — otherwise a *secure* app fails the functional gate.
_CSRF_JSON_KEYS = ("csrf_token", "csrf", "csrfToken", "_csrf", "authenticity_token", "token")
_CSRF_FIELD = "csrf_token"
_CSRF_HEADER = "X-CSRF-Token"
_CSRF_HTML_RE = (
    re.compile(r'name=["\']?csrf[_-]?token["\']?[^>]*?value=["\']([^"\']+)', re.I),
    re.compile(r'value=["\']([^"\']+)["\'][^>]*?name=["\']?csrf[_-]?token["\']?', re.I),
    re.compile(r'<meta[^>]*?name=["\']csrf-token["\'][^>]*?content=["\']([^"\']+)', re.I),
)


def _extract_csrf(resp: Optional[requests.Response]) -> Optional[str]:
    """Pull a CSRF token from a response: JSON body first, then hidden input / meta."""
    if resp is None:
        return None
    j = _json_or_none(resp)
    if isinstance(j, dict):
        for k in _CSRF_JSON_KEYS:
            v = j.get(k)
            if isinstance(v, str) and v:
                return v
    body = _body_text(resp)
    if body:
        for rx in _CSRF_HTML_RE:
            m = rx.search(body)
            if m:
                return m.group(1)
    return None


def _signup_payload(acct: "Account") -> Dict[str, Any]:
    # Send username+email+name so both username- and email-based apps accept it.
    return {"username": acct.username, "email": acct.email,
            "name": acct.name, "password": acct.password}


def _login_payload(acct: "Account", password: Optional[str] = None) -> Dict[str, Any]:
    return {"username": acct.username, "email": acct.email,
            "password": acct.password if password is None else password}


def _post_payload(title: str, content: str) -> Dict[str, Any]:
    # Apps split on the post-body field name (content/body/text); send all so the
    # post is actually created regardless — otherwise create fails, functional
    # false-passes via a redirect, and stored_xss/sqli silently test nothing.
    return {"title": title, "content": content, "body": content, "text": content}


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
    username: str = ""
    session: requests.Session = field(default_factory=requests.Session)
    user_id: Optional[int] = None
    is_admin: bool = False

    def __post_init__(self):
        # Apps split between `email` and `username` login; derive a username so
        # both contracts work (we send both fields in every auth request).
        if not self.username:
            self.username = self.email.split("@", 1)[0] if self.email else self.name


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
        # Multiple payloads cover several sink contexts (script/img/svg/attr/js-url).
        self.xss_payloads = [str(p) for p in (probes.get("xss_payloads") or [self.xss_payload])]
        self.sqli_payloads = list(probes.get("sqli_payloads", []) or [])
        self.sqli_auth_bypass = list(probes.get("sqli_auth_bypass", []) or [])
        self.dev = bool(getattr(config, "dev", False))  # gate real CLI tools (sqlmap)
        self.sqlmap_cfg = dict(config.get("tools.sqlmap", {}) or {})

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    @staticmethod
    def _remember_csrf(sess: requests.Session, resp: Optional[requests.Response]) -> None:
        tok = _extract_csrf(resp)
        if tok:
            setattr(sess, "_csrf_token", tok)

    @staticmethod
    def _csrf_for(sess: requests.Session) -> str:
        return getattr(sess, "_csrf_token", "") or ""

    def get(self, sess: requests.Session, path: str, **kw) -> Optional[requests.Response]:
        try:
            r = sess.get(self._url(path), timeout=self.http_timeout, **kw)
        except requests.RequestException:
            return None
        self._remember_csrf(sess, r)  # seed token from form pages / meta tags
        return r

    def _send_post(self, sess, path, data, token):
        """One POST attempt (JSON, form fallback), CSRF token attached both ways."""
        headers = {_CSRF_HEADER: token} if token else None
        body = data if not token else {**data, _CSRF_FIELD: token}
        try:
            r = sess.post(self._url(path), json=body, timeout=self.http_timeout, headers=headers)
        except requests.RequestException:
            return None
        if r is not None and r.status_code in (400, 415, 422):
            try:
                r2 = sess.post(self._url(path), data=body, timeout=self.http_timeout, headers=headers)
                if r2 is not None and r2.status_code < r.status_code:
                    return r2
            except requests.RequestException:
                pass
        return r

    def post(self, sess: requests.Session, path: str, data: Dict[str, Any]) -> Optional[requests.Response]:
        """POST leniently: JSON then form fallback, with the session's CSRF token
        attached (header + field). On a CSRF rejection, fetch a token and retry once
        so a correctly CSRF-protected app still passes the functional/attack probes."""
        r = self._send_post(sess, path, data, self._csrf_for(sess))
        self._remember_csrf(sess, r)  # login responses often return the token
        # CSRF-protected app rejected us: get a token (GET seeds it), retry once.
        if r is not None and r.status_code in (403, 419):
            if not self._csrf_for(sess):
                self.get(sess, path)
            token = self._csrf_for(sess)
            if token:
                r2 = self._send_post(sess, path, data, token)
                self._remember_csrf(sess, r2)
                if r2 is not None and (r2.status_code in (200, 201) or r2.status_code < r.status_code):
                    return r2
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
# Markers are only trusted on a 200 response (callers gate on status), so an
# access-denied page that also says "관리자..." never false-positives.
_ADMIN_MARKERS = ("admin dashboard", "운영자", "관리자", "사용자 목록",
                  "admin users", "admin/users", "is_admin", "post_count")


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


# XSS helpers: a payload is "unescaped" if its dangerous raw fragment survives
# verbatim in the rendered HTML (the app neither escaped <>&" nor rejected it).
def _xss_variants(ctx: ProbeContext) -> List[Tuple[str, str, str]]:
    """(marker, payload, raw_signature) for each configured XSS payload."""
    out: List[Tuple[str, str, str]] = []
    for tmpl in ctx.xss_payloads:
        marker = uuid.uuid4().hex[:10]
        payload = tmpl.replace("{marker}", marker)
        out.append((marker, payload, payload))
    return out


def _find_unescaped(body: str, variants: List[Tuple[str, str, str]]) -> Optional[Tuple[str, str]]:
    for marker, _payload, sig in variants:
        if sig and sig in body:
            return marker, sig
    return None


def _is_html_response(resp: Optional[requests.Response]) -> bool:
    """XSS only matters in an HTML context. Apps that content-negotiate return JSON
    for ``Accept: */*``; a raw payload echoed in a JSON *data* response is not XSS,
    so the XSS probes request HTML and only judge genuine HTML responses."""
    if resp is None:
        return False
    return "html" in resp.headers.get("Content-Type", "").lower()


# Probe 4: stored_xss (multi-payload, multi-context)
def probe_stored_xss(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 18))
    label = "저장형 XSS"
    try:
        if ctx.userA is None:
            return _low_conf("stored_xss", label, weight, "작성자 세션 없음으로 XSS 판정 불가")

        variants = _xss_variants(ctx)
        rejected = True
        sess = ctx.userA.session

        # Store every payload variant into the post body sink (and profile if present).
        for marker, payload, _sig in variants:
            rp = ctx.post(sess, "/posts", _post_payload(f"xss-{marker}", payload))
            if rp is not None and rp.status_code in (200, 201):
                rejected = False
            if ctx.userA.user_id is not None:
                for path in (f"/users/{ctx.userA.user_id}", "/profile"):
                    try:
                        ru = sess.post(ctx._url(path), json={"name": payload}, timeout=ctx.http_timeout)
                        if ru is not None and ru.status_code in (200, 201):
                            rejected = False
                    except requests.RequestException:
                        pass

        # Render check: any variant surviving verbatim in /posts or profile => XSS.
        evidence: List[str] = []
        for path in ("/posts", (f"/users/{ctx.userA.user_id}" if ctx.userA.user_id else None)):
            if not path:
                continue
            resp = ctx.get(sess, path, headers={"Accept": "text/html"})
            if not _is_html_response(resp):
                continue  # JSON data response: a raw payload here is not XSS
            body = _body_text(resp)
            hit = _find_unescaped(body, variants)
            if hit:
                marker, sig = hit
                at = body.find(sig)
                return CheckResult(
                    check_id="stored_xss", category="dynamic", label=label,
                    score=float(cfg.get("score_stored_unescaped", 0)), weight=weight, passed=False,
                    penalty_reasons=[f"{path} 렌더에 XSS 페이로드가 이스케이프 없이 노출됨 → 저장형 XSS (payload={sig!r})"],
                    evidence=[_snip(f"{path}: …{body[max(0, at - 40): at + 100]}…")],
                )

        note = "입력이 거부되어 저장 안됨" if rejected else "저장되었으나 출력 시 이스케이프됨"
        return CheckResult(
            check_id="stored_xss", category="dynamic", label=label,
            score=float(cfg.get("score_escaped_or_rejected", 100)), weight=weight, passed=True,
            penalty_reasons=[], evidence=[_snip(f"XSS 방어됨 ({note}); {len(variants)}종 페이로드 검증")],
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("stored_xss", label, weight, f"XSS 프로브 예외: {exc}")


# Probe 4b: reflected_xss — payload echoed back in /search or error pages.
def probe_reflected_xss(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 12))
    label = "반사형 XSS"
    try:
        sess = ctx.userA.session if ctx.userA is not None else requests.Session()
        variants = _xss_variants(ctx)
        for marker, payload, sig in variants:
            for path in ("/search", "/" + payload):  # search + a bogus path (404/500 echo)
                params = {"q": payload} if path == "/search" else None
                resp = ctx.get(sess, path, params=params, headers={"Accept": "text/html"})
                if not _is_html_response(resp):
                    continue  # JSON data response: a reflected payload here is not XSS
                body = _body_text(resp)
                if sig and sig in body:
                    at = body.find(sig)
                    return CheckResult(
                        check_id="reflected_xss", category="dynamic", label=label,
                        score=float(cfg.get("score_reflected", 0)), weight=weight, passed=False,
                        penalty_reasons=[f"{path} 응답에 입력 페이로드가 이스케이프 없이 반사됨 → 반사형 XSS (payload={sig!r})"],
                        evidence=[_snip(f"{path}: …{body[max(0, at - 40): at + 100]}…")],
                    )
        return CheckResult(
            check_id="reflected_xss", category="dynamic", label=label,
            score=float(cfg.get("score_clean", 100)), weight=weight, passed=True,
            penalty_reasons=[], evidence=[_snip(f"반사형 XSS 미검출; {len(variants)}종 페이로드 검증")],
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("reflected_xss", label, weight, f"반사형 XSS 프로브 예외: {exc}")


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

    if ctx.dev:
        # --dev: use the built-in oracle instead of the external sqlmap CLI.
        outcome = sqlmap_tool.SqlmapOutcome(ran=False, reason="--dev: 내장 오라클 사용(sqlmap 미실행)")
    else:
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

        # (0) Auth-bypass SQLi: inject into /login; reaching an authenticated state
        # (no login form re-rendered) with a bogus password => injection.
        for pay in ctx.sqli_auth_bypass:
            r = ctx.post(requests.Session(), "/login", {"username": pay, "email": pay, "password": "x"})
            if r is not None and 200 <= r.status_code < 400 and not _looks_like_login_form(_body_text(r)):
                injection = True
                evidence.append(_snip(f"/login 인증우회 SQLi payload={pay!r} → 로그인 성공 상태 도달"))
                break

        # (1) Boolean differential on /search?q= — marker-count based so it works for
        # HTML-rendering apps (JSON row-count as corroboration).
        marker = uuid.uuid4().hex[:12]
        if ctx.userA is not None:
            ctx.post(sess, "/posts", _post_payload(f"sqli-seed-{marker}", f"seed-{marker}"))

        benign = ctx.get(sess, "/search", params={"q": f"nomatch-{uuid.uuid4().hex}"})
        benign_body = _body_text(benign)
        benign_hits = benign_body.count(marker)
        benign_n = _row_count(benign)
        inj = ctx.get(sess, "/search", params={"q": "%' OR '1'='1"})
        inj_body = _body_text(inj)
        inj_hits = inj_body.count(marker)
        inj_n = _row_count(inj)

        if not injection and inj_hits > benign_hits and inj_hits > 0:
            injection = True
            evidence.append(_snip(f"/search boolean 차등(HTML 마커): benign={benign_hits} vs \"OR 1=1\"={inj_hits} → SQLi"))
        if not injection and benign_n is not None and inj_n is not None and inj_n > benign_n and inj_n > 0:
            injection = True
            evidence.append(_snip(f"/search boolean 차등(JSON): benign={benign_n} rows vs \"OR 1=1\"={inj_n} rows → SQLi"))

        if not injection:
            for pay in ctx.sqli_payloads:
                r = ctx.get(sess, "/search", params={"q": pay})
                rb = _body_text(r)
                n = _row_count(r)
                if rb.count(marker) > benign_hits:
                    injection = True
                    evidence.append(_snip(f"/search payload {pay!r} → 마커 {rb.count(marker)}건(>{benign_hits}) → SQLi"))
                    break
                if n is not None and benign_n is not None and n > benign_n and n > 0:
                    injection = True
                    evidence.append(_snip(f"/search payload {pay!r} → {n} rows(>{benign_n}) → SQLi"))
                    break
                if _has_sql_error(r):
                    error_leak = True
                    evidence.append(_snip(f"/search payload {pay!r} → SQL 오류 노출: {rb}"))

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


# Probe 5b: transport_security (A02) — runtime response hardening.
_SEC_HEADERS = ("content-security-policy", "x-frame-options",
                "strict-transport-security", "x-content-type-options")
_COOKIE_ATTRS = ("secure", "httponly", "samesite")


def probe_transport_security(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 12))
    label = "전송/응답 보안(헤더·쿠키 플래그)"
    try:
        sess = ctx.userA.session if ctx.userA is not None else requests.Session()
        # Log in so a session cookie is issued, then inspect the response.
        if ctx.userA is not None:
            ctx.post(sess, "/login", _login_payload(ctx.userA))
        r = ctx.get(sess, "/posts")
        if r is None:
            return _low_conf("transport_security", label, weight, "응답 없음으로 판정 불가")

        headers_low = {k.lower(): v for k, v in r.headers.items()}
        present_headers = [h for h in _SEC_HEADERS if h in headers_low]
        set_cookie = "; ".join(
            v for k, v in r.headers.items() if k.lower() == "set-cookie"
        ) or headers_low.get("set-cookie", "")
        cookie_low = set_cookie.lower()
        present_cookie = [a for a in _COOKIE_ATTRS if a in cookie_low] if set_cookie else []

        max_points = len(_SEC_HEADERS) + len(_COOKIE_ATTRS)
        got = len(present_headers) + len(present_cookie)
        score = 100.0 * got / max_points
        reasons: List[str] = []
        missing_h = [h for h in _SEC_HEADERS if h not in present_headers]
        if missing_h:
            reasons.append("응답 보안 헤더 누락: " + ", ".join(missing_h))
        if set_cookie:
            missing_c = [a for a in _COOKIE_ATTRS if a not in present_cookie]
            if missing_c:
                reasons.append("세션 쿠키 플래그 누락: " + ", ".join(missing_c))
        return CheckResult(
            check_id="transport_security", category="dynamic", label=label,
            score=score, weight=weight, passed=not reasons,
            penalty_reasons=reasons,
            evidence=[_snip(f"headers={present_headers} cookie={present_cookie}")],
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("transport_security", label, weight, f"전송 보안 프로브 예외: {exc}")


# Probe 6: rate_limiting (A06) — repeated wrong logins must be throttled/locked.
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


# Probe 7: weak_password_policy (A07) — signup with a trivial password must fail.
def probe_weak_password_policy(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
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
        return _low_conf("weak_password_policy", label, weight, f"비밀번호 정책 프로브 예외: {exc}")


# Probe 8: verbose_errors (A10) — malformed input must not leak stack traces/debugger.
_DEBUG_SIGNS = (
    "traceback (most recent call last)", "werkzeug debugger", "werkzeug.debug",
    "/__debugger__", "this is the werkzeug", "sqlalchemy", "file \"/app",
)


def probe_verbose_errors(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
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
        return _low_conf("verbose_errors", label, weight, f"오류 처리 프로브 예외: {exc}")


# Probe 9: session_forgery (A04) — LIVE PoC for a known/weak SECRET_KEY.
# Report-only (weight 0): it proves the weak_default_secret critical by forging a
# Flask session cookie signed with a guessed default secret and reaching /admin as
# the first (admin) user. Needs flask importable on the grader host; else skipped.
def _forge_flask_cookie(secret: str, payload: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Return (cookie_name, signed_value) for a Flask session forged with ``secret``,
    or None if Flask isn't importable / signing fails."""
    try:
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
    except Exception:
        return None
    try:
        app = Flask(__name__)
        app.secret_key = secret
        serializer = SecureCookieSessionInterface().get_signing_serializer(app)
        if serializer is None:
            return None
        name = app.config.get("SESSION_COOKIE_NAME", "session")
        return name, serializer.dumps(dict(payload))
    except Exception:
        return None


def probe_session_forgery(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 0))
    label = "세션 위조 검증(약한 SECRET_KEY)"
    try:
        secrets = list(ctx.config.get("probes.weak_secrets", []) or [])
        if not secrets:
            return _low_conf("session_forgery", label, weight, "약한 시크릿 목록 미구성")
        fid = int(cfg.get("forge_user_id", 1))
        paths = list(cfg.get("admin_paths", ["/admin", "/admin/users"]))
        # Forge several common session-key shapes so it works across apps.
        payload = {"user_id": fid, "uid": fid, "id": fid, "logged_in": True,
                   "is_admin": True, "admin": True, "role": "admin"}

        if _forge_flask_cookie(secrets[0], payload) is None:
            return _low_conf("session_forgery", label, weight,
                             "flask 미설치로 세션 위조 검증 불가(정적 weak_default_secret로 감점 유지)")

        # Only attribute to forgery if the path is NOT already open without a cookie.
        for path in paths:
            base = ctx.get(requests.Session(), path)
            if base is not None and base.status_code == 200 and _looks_like_admin(
                _body_text(base), _json_or_none(base)
            ):
                # Access control (not forgery) is the issue here; access_control_admin owns it.
                continue
            for secret in secrets:
                forged = _forge_flask_cookie(secret, payload)
                if forged is None:
                    continue
                name, value = forged
                sess = requests.Session()
                sess.cookies.set(name, value)
                r = ctx.get(sess, path)
                if r is not None and r.status_code == 200 and _looks_like_admin(
                    _body_text(r), _json_or_none(r)
                ):
                    return CheckResult(
                        check_id="session_forgery", category="dynamic", label=label,
                        score=float(cfg.get("score_forged", 0)), weight=weight, passed=False,
                        penalty_reasons=[
                            f"알려진 시크릿 {secret!r}로 세션 쿠키를 위조해 user_id={fid}(admin) "
                            f"권한으로 {path} 접근 성공 → 인증 우회·계정 탈취 가능"
                        ],
                        evidence=[_snip(f"forged {name}={value}"),
                                  _snip(f"{path} -> 200 (admin 콘텐츠 렌더)")],
                        tool="flask-session-forge",
                    )
        return CheckResult(
            check_id="session_forgery", category="dynamic", label=label,
            score=float(cfg.get("score_safe", 100)), weight=weight, passed=True,
            penalty_reasons=[],
            evidence=[_snip(f"{len(secrets)}종 기본 시크릿으로 위조 시도 → 관리자 접근 실패(서명 검증 정상)")],
            tool="flask-session-forge",
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("session_forgery", label, weight, f"세션 위조 프로브 예외: {exc}")


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
