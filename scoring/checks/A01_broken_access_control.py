"""A01 Broken Access Check (SSRF folded in for 2025): the CSRF-protection static
check, plus the IDOR, admin access-control, privilege-escalation, admin
user-management and live SSRF-callback probes.

SSRF is judged ONLY dynamically (``dynamic_ssrf``): the former static ``ssrf_sink``
check was removed because "an outbound fetch with a non-literal URL" cannot separate
a guarded implementation from an exploitable one without real dataflow analysis.

The object-level authorization (BOLA) probes — ``object_authorization`` (post
edit/delete) and ``comment_authorization`` (comment edit/delete) — were REMOVED: both
depended on pinning a post/comment id and on an owner "positive control" landing, so
an app whose response shape hid those ids was accused or skipped on grader-side
discovery failures rather than on its actual authorization. Do not re-add them.
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Optional

import requests

from ..shared.http import (
    _body_text, _json_or_none, _login_payload, _looks_like_admin,
    _looks_like_login_form, _post_payload, _snip, admin_access, create_post_id,
    new_account, post_ids, record_id, shows_number,
)
from .base import Check, _undecidable, result


# ── csrf_protection  (dynamic) — effect-based: a forged cross-site form POST.
# A same-origin control post (with whatever token the app hands out) must work; the
# forged one (no token, attacker Origin/Referer, victim's cookie) must not create the
# post. A token, Flask-WTF or a strict Origin/Referer check all pass the same way.
# When the forgery goes through server-side, SameSite=Lax/Strict on the session cookie
# still stops it in browsers — partial (ASVS 5.0 3.5.1 L1 wants an explicit defense).
def _session_samesite(acct) -> Optional[bool]:
    """Whether the cookie the app set on ``acct``'s earlier login is SameSite=Lax/
    Strict, read from the session's cookie jar. Logging in again to look would end
    the live session of an app that keeps one session per user. ``None`` when the
    jar holds no cookie, so there is nothing to tell."""
    cookies = list(acct.session.cookies)
    if not cookies:
        return None
    return any(str(v or "").lower() in ("lax", "strict")
               for c in cookies for k, v in getattr(c, "_rest", {}).items()
               if k.lower() == "samesite")


def _listed(ctx, title: str) -> Optional[bool]:
    """Whether a post titled ``title`` is in the list (newest first, then the default
    order). Never search: a search page echoes the query, so the title would always
    "appear". The control post is looked up the same way, so a list that doesn't
    show new posts makes the probe undecidable, never a false pass."""
    answered = False
    for path in ("/posts?sort=newest", "/posts"):
        r = ctx.get(requests.Session(), path)
        if r is None or r.status_code >= 500:
            continue
        answered = True
        if title in _body_text(r):
            return True
    return False if answered else None


def dynamic_csrf_protection(check, ctx, cfg):
    acct = ctx.userA
    if acct is None:
        return _undecidable(check, cfg, "테스트 계정 없음으로 판정 불가")
    tag = uuid.uuid4().hex[:10]
    ctl, forged = f"csrf-ctl-{tag}", f"csrf-forged-{tag}"
    ctx.post(acct.session, "/posts", _post_payload(ctl, ctl))
    if not _listed(ctx, ctl):
        return _undecidable(check, cfg, "정상 글 작성이 목록에 보이지 않아 CSRF 판정 불가")

    r = ctx.cross_site_post(acct.session, "/posts", _post_payload(forged, forged))
    if r is None:
        return _undecidable(check, cfg, "위조 요청에 응답이 없어 판정 불가")
    # Judged by the write, not the status: an app whose CSRF guard crashes into a 500
    # still refused the forged post if it never lands.
    landed = _listed(ctx, forged)
    if landed is None:
        return _undecidable(check, cfg, "글 목록 확인 불가로 판정 불가")
    if not landed:
        return result(check, cfg, score=cfg.get("score_protected", 100), passed=True,
                      evidence=[_snip(f"외부 Origin·토큰 없는 POST /posts -> {r.status_code}, 글 생성 안 됨")])
    evidence = [_snip(f"외부 Origin(http://evil.example)·토큰 없는 POST /posts -> {r.status_code}, 글 생성됨")]
    samesite = _session_samesite(acct)
    if samesite:
        return result(check, cfg, score=cfg.get("score_samesite_only", 50), passed=False,
                      reasons=["토큰·Origin 검증 없이 SameSite 쿠키에만 의존 → 브라우저 정책 의존(ASVS 3.5.1은 토큰 등 명시적 방어 요구)"],
                      evidence=evidence)
    if samesite is None:
        return _undecidable(check, cfg, "세션 쿠키가 없어 SameSite 판정 불가")
    return result(check, cfg, score=cfg.get("score_missing", 0), passed=False,
                  reasons=["외부 사이트 폼으로 로그인 사용자의 글 작성이 위조됨 → CSRF(토큰·Origin 검증·SameSite 모두 없음)"],
                  evidence=evidence)


# ── idor_profile  (dynamic) ────────────────────────────────────────────────
def dynamic_idor_profile(check, ctx, cfg):
    if ctx.userA is None or ctx.userB is None:
        return _undecidable(check, cfg, "테스트 계정 구성 부족으로 IDOR 판정 불가")
    # IDOR keys on phone, a strictly private PII field: it must NOT appear to another
    # user. userB reading userA's phone off the profile = CWE-639 PII leak.
    if not ctx.userA.phone:
        return _undecidable(check, cfg, "userA의 phone(사적 PII)이 없어 IDOR 판정 불가")
    if ctx.userA.user_id is None:
        ctx.userA.user_id = _discover_user_id(ctx, ctx.userA)
    if ctx.userA.user_id is None:
        return _undecidable(check, cfg, "userA의 id를 확인할 수 없어 IDOR 판정 불가")

    phone = _digits(ctx.userA.phone)
    target = f"/users/{ctx.userA.user_id}"
    # Control: userA sees own phone on own profile. Attack: userB reads userA's.
    # Both probe the HTML surface AND the JSON representation (see _reads_phone) —
    # apps commonly keep phone (private PII) out of the rendered profile page and
    # only return it via JSON, so an HTML-only read mis-scored a correctly
    # access-controlled app "control broken" and also missed JSON-only PII leaks.
    control_ok, ctrl_code, ctrl_body = _reads_phone(ctx, ctx.userA.session, target, phone)
    leaked, atk_code, atk_body = _reads_phone(ctx, ctx.userB.session, target, phone)

    evidence = [_snip(f"userA self {target} -> {ctrl_code}: {ctrl_body}"),
                _snip(f"userB attack {target} -> {atk_code}: {atk_body}")]

    if leaked:
        return result(check, cfg, score=cfg.get("score_leaked", 0), passed=False,
                      reasons=[f"userB 세션으로 userA({ctx.userA.phone}) 전화번호 조회됨 → IDOR/PII 노출"],
                      evidence=evidence)
    if not control_ok:
        # Couldn't confirm the phone is exposed to its owner on any surface. If the
        # attacker got an explicit denial (401/403/404), access control is
        # demonstrably enforced (or there is simply no phone-leaking surface to
        # exploit) — credit the defense rather than docking a working app. Only the
        # murky case (attacker got 200 but no phone, owner couldn't show it either)
        # stays "control broken".
        if atk_code in (401, 403, 404):
            return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                          reasons=["본인 전화번호가 프로필에 노출되지 않아 대조군은 못 세웠으나 "
                                   f"공격자 접근이 차단됨(HTTP {atk_code}) → 접근 통제 정상"],
                          evidence=evidence)
        # Neither the owner nor the attacker sees the phone and nothing was denied:
        # there's no observable PII surface, so it can't be judged (skip, not 0).
        return _undecidable(check, cfg,
                            "본인 전화번호도 프로필에 나오지 않아 IDOR 판정 불가(대조군 없음)")
    # Defended: masked / 403 / 404 for the attacker. Sequential integer ids are NOT
    # penalized — the app contract (프롬프트) mandates them (id 순번 + admin=id1), so
    # they're a grader-imposed constraint, not a participant choice.
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip(f"userB attack {target} -> {atk_code} (전화번호 미노출/차단)")])


def _digits(s: str) -> str:
    """Strip everything but digits so a phone match survives app-side reformatting
    (spaces/dashes/parens/+)."""
    return re.sub(r"\D", "", s or "")


def _reads_phone(ctx, sess, target, phone):
    """GET ``target`` and report whether ``phone``'s digits appear in a 200 body.
    Tries the default (HTML) surface first, then the JSON representation
    (``Accept: application/json``) — apps often keep phone out of the rendered page
    but return it in JSON. Returns ``(matched, status_code, body_text)`` for the
    response that decided it (the last one tried if none matched)."""
    last_code: Optional[int] = None
    last_body = ""
    for headers in (None, {"Accept": "application/json"}):
        r = ctx.get(sess, target, headers=headers)
        last_code = r.status_code if r is not None else None
        last_body = _body_text(r)
        if last_code == 200 and shows_number(last_body, phone):
            return True, last_code, last_body
    return False, last_code, last_body


def _discover_user_id(ctx, acct) -> Optional[int]:
    """If login didn't return an id, probe /users/<n> with the account's own
    session and match its phone (digit-robust, HTML+JSON) to find its id."""
    if acct is None or not acct.phone:
        return None
    phone = _digits(acct.phone)
    linked: List = []
    for page in ("/profile", "/me", "/posts"):
        for m in re.findall(r"""/users/([^/"'?#\s<>]+)""", _body_text(ctx.get(acct.session, page))):
            if record_id(m) is not None and m not in linked:
                linked.append(m)
    for uid in [*linked, *range(1, 11)]:
        ok, _, _ = _reads_phone(ctx, acct.session, f"/users/{uid}", phone)
        if ok:
            return uid
    return None


# ── access_control_admin  (dynamic) ────────────────────────────────────────
def dynamic_access_control_admin(check, ctx, cfg):
    if ctx.userB is None:
        return _undecidable(check, cfg, "일반 사용자 세션 없음으로 판정 불가")

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

    if exposed_paths:
        reasons = [f"일반 사용자(userB) 세션으로 {p} 노출됨 → 접근 통제 실패" for p in exposed_paths]
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=reasons, evidence=evidence)
    if None in codes.values():
        return _undecidable(check, cfg, "관리자 페이지 요청에 응답이 없어 판정 불가")
    # Blocked (403/404/redirect/login form) => defended. No 404 "concealment" bonus:
    # the contract fixes the /admin path, so hiding it is not a participant lever.
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True, evidence=evidence)


# ── privilege_escalation  (dynamic) — mass assignment: does /signup trust a
# client-supplied is_admin/role field?
_PRIVESC_FIELDS = {"is_admin": True, "admin": True, "role": "admin", "is_staff": True}


def dynamic_privilege_escalation(check, ctx, cfg):
    """PoC: sign up while sending is_admin/role in the body. If that account reaches
    the admin area while a plain-signup control does not, the app trusted a
    client-set privilege field (mass assignment)."""
    extra = dict(cfg.get("admin_fields") or _PRIVESC_FIELDS)
    attacker = new_account(ctx, "pe_", login=True, password="Booth!Secure2345", extra=extra)
    control = new_account(ctx, "pe_", login=True, password="Booth!Secure2345")
    if attacker is None or control is None:
        return _undecidable(check, cfg, "가입/로그인 실패로 권한상승 판정 불가")

    attacker, control = attacker.session, control.session
    ctl_path, ctl_answered = admin_access(ctx, control)
    if ctl_path is not None:
        # Admin area is open to ANY signup: the attacker is admin already. Failed, but
        # unproven so the critical is access_control_admin's alone (no double penalty).
        return result(check, cfg, score=cfg.get("score_escalated", 0), passed=False, unproven=True,
                      reasons=[f"일반 가입자도 {ctl_path}에 들어감. 감점은 관리자 페이지 접근 통제에서 한 번만"],
                      evidence=[_snip(f"일반 가입 → GET {ctl_path} 관리자 콘텐츠 노출")])

    atk_path, atk_answered = admin_access(ctx, attacker)
    if atk_path is None and not (ctl_answered and atk_answered):
        return _undecidable(check, cfg, "관리자 페이지 요청에 응답이 없어 판정 불가")
    if atk_path is not None:
        return result(check, cfg, score=cfg.get("score_escalated", 0), passed=False,
                      reasons=[f"가입 요청의 {sorted(extra)} 필드를 신뢰 → 관리자 권한 탈취({atk_path})"],
                      evidence=[_snip(f"is_admin 포함 가입 → GET {atk_path} 관리자 콘텐츠 노출 / 대조군(일반 가입)은 차단")])
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip("is_admin 주입 가입도 관리자 접근 불가 → Mass Assignment 방어됨")])


# ── ssrf  (dynamic) — LIVE server-side request forgery. Hand the app a callback URL
# on the container's host-gateway (a PRIVATE address); if the server fetches it, the
# callback fires => it makes outbound requests to attacker-chosen private/host targets
# with no egress filtering. Effect-based (a real fetch landed), not a static sink guess.
def dynamic_ssrf(check, ctx, cfg):
    cb = getattr(ctx, "ssrf_callback", None)
    hosts = list(getattr(ctx, "ssrf_hosts", []) or [])
    if cb is None or not hosts or getattr(cb, "port", None) is None:
        return _undecidable(check, cfg,
                            "SSRF 콜백 리스너 미가동으로 판정 불가")
    if ctx.userA is None:
        return _undecidable(check, cfg, "테스트 계정 부족으로 SSRF 판정 불가")

    # Submit one distinct callback URL per reachable host (host.docker.internal + the
    # bridge gateway IP). URL-consuming surfaces: post link preview + avatar-by-URL.
    codes: List = []
    tokens: List[str] = []
    for host in hosts:
        token = "ssrf-" + uuid.uuid4().hex[:12]
        tokens.append(token)
        cb_url = cb.url_for(token, host)
        r = ctx.post(ctx.userA.session, "/posts",
                     {**_post_payload(f"ssrf-{token}", f"ssrf-{token}"), "link_url": cb_url, "url": cb_url})
        r2 = ctx.post(ctx.userA.session, "/profile/avatar", {"avatar_url": cb_url})
        codes += [getattr(r, "status_code", None), getattr(r2, "status_code", None)]
    _view_submitted(ctx, len(hosts))

    # The fetch may be async; poll the callback briefly for ANY submitted token.
    if _callback_hit(cb, tokens, cfg):
        return result(check, cfg, score=cfg.get("score_vulnerable", 0), passed=False,
                      reasons=["서버가 공격자 지정 사설/호스트 주소를 가져옴 → SSRF(사설 대역 미차단)"],
                      evidence=[_snip("link_url/avatar_url 제출 → 그레이더 콜백 히트: 서버측 요청 확인")])

    # Redirect bypass: a PUBLIC-looking URL that 302s to the private callback. Apps
    # that check only the first host and let the client follow redirects fall here.
    redirect = getattr(ctx, "ssrf_redirect", None)
    if redirect is not None:
        rtokens: List[str] = []
        for host in hosts:
            token = "ssrfr-" + uuid.uuid4().hex[:12]
            rtokens.append(token)
            via = redirect(cb.url_for(token, host))
            if via:
                ctx.post(ctx.userA.session, "/posts",
                         {**_post_payload(f"ssrf-{token}", f"ssrf-{token}"), "link_url": via, "url": via})
                ctx.post(ctx.userA.session, "/profile/avatar", {"avatar_url": via})
        _view_submitted(ctx, len(hosts))
        if _callback_hit(cb, rtokens, cfg):
            return result(check, cfg, score=cfg.get("score_vulnerable", 0), passed=False,
                          reasons=["공개 주소로 위장한 URL의 302 리다이렉트를 따라가 사설/호스트 주소를 가져옴 "
                                   "→ SSRF(리다이렉트 경유 필터 우회)"],
                          evidence=[_snip("공개 IP 리다이렉터 → 그레이더 사설 콜백 히트: 최초 호스트만 검사")])

    # Positive control: the private-address callback stayed silent — credit a defense
    # only if the preview feature demonstrably fetches a PUBLIC URL; otherwise the app
    # may simply not fetch anything (feature missing ≠ SSRF-safe). Rejecting the
    # private URL outright (400) is a defense too, so it is judged the same way: the
    # control decides whether the feature exists, not the attack's status code.
    if not _preview_fetches_public_url(ctx, cfg):
        # No server-side fetch at all: nothing for an attacker to steer. A missing
        # preview is the contract's finding (R18), not an SSRF.
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                      evidence=[_snip(f"사설·호스트 주소 제출 응답 {codes}, 콜백 호출 없음"),
                                _snip("공개 주소도 가져오지 않음 → 서버 측 요청 없음")])
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip(f"사설·호스트 주소 제출 응답 {codes}, 콜백 호출 없음"),
                            _snip("공개 주소 미리보기는 동작 → 내부 주소 차단")])


def _view_submitted(ctx, n: int) -> None:
    """Open what a visitor would: the list, the newest ``n`` posts and the profile.
    Apps that fetch the link preview or avatar URL only when it is VIEWED fire then."""
    sess = ctx.userA.session
    ids: List = []
    for path in ("/posts?sort=newest", "/posts"):
        ids += [i for i in post_ids(_body_text(ctx.get(sess, path))) if i not in ids]
    for pid in ids[:n]:
        ctx.get(sess, f"/posts/{pid}")
    if ctx.userA.user_id is not None:
        ctx.get(sess, f"/users/{ctx.userA.user_id}")
    ctx.get(sess, "/profile")


def _callback_hit(cb, tokens: List[str], cfg) -> bool:
    deadline = time.monotonic() + float(cfg.get("wait_seconds", 3))
    while time.monotonic() < deadline:
        if any(cb.was_hit(t) for t in tokens):
            return True
        time.sleep(0.2)
    return False


def _preview_fetches_public_url(ctx, cfg) -> bool:
    """Post a public control URL and look for its page title in the rendered post —
    proof the server fetches URLs. The grader's own public page when the redirector
    runs (no internet needed), else ``control_url``/``control_marker``."""
    page = getattr(ctx, "ssrf_public_page", None)
    if page and page[0]:
        url, marker = page
    else:
        url = str(cfg.get("control_url", "http://example.com/"))
        marker = str(cfg.get("control_marker", "Example Domain"))
    content = "ssrf-ctl-" + uuid.uuid4().hex[:12]
    pid = create_post_id(ctx, ctx.userA.session, content, content, {"link_url": url, "url": url})
    if pid is None:
        return False
    return marker in _body_text(ctx.get(ctx.userA.session, f"/posts/{pid}"))


# ── admin_user_mgmt  (dynamic) — a normal user must not run admin user-management.
def dynamic_admin_user_mgmt(check, ctx, cfg):
    """PoC: userB calls the role-change endpoint on ITSELF, then checks whether it
    now reaches /admin. Effect-based (an actual self-promotion), so a soft-deny 200
    from the endpoint isn't a false hit. Non-destructive — touches no other account."""
    if ctx.userB is None:
        return _undecidable(check, cfg, "일반 사용자 세션 없음으로 판정 불가")
    # If the admin area is already open to any user, that is access_control_admin's
    # finding — don't double-judge (would double-penalize the same defect).
    open_path, open_answered = admin_access(ctx, ctx.userB.session)
    if open_path is not None:
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False, unproven=True,
                      reasons=[f"일반 사용자도 {open_path}에 들어감. 감점은 관리자 페이지 접근 통제에서 한 번만"],
                      evidence=[_snip(f"userB GET {open_path} 관리자 콘텐츠 노출")])

    uid = ctx.userB.user_id or _discover_user_id(ctx, ctx.userB)
    if uid is None:
        return _undecidable(check, cfg, "userB id 확인 불가로 판정 불가")

    ctx.post(ctx.userB.session, f"/admin/users/{uid}/role", {"role": "admin", "is_admin": True})
    reached, answered = admin_access(ctx, ctx.userB.session)
    if reached is not None:
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=[f"userB가 /admin/users/{uid}/role 로 스스로 관리자 승격 → 관리자 사용자관리 인가 실패"],
                      evidence=[_snip(f"일반 사용자 역할변경 후 {reached} 관리자 접근 획득")])
    if not (open_answered and answered):
        return _undecidable(check, cfg, "관리자 페이지 요청에 응답이 없어 판정 불가")
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip("일반 사용자의 역할 변경 시도가 관리자 권한으로 이어지지 않음")])


# ── open_redirect  (dynamic) ───────────────────────────────────────────────
# Spec: POST /login with `next` (query or form) redirects there after login. An app
# that redirects to any `next` hands attackers a trusted-looking phishing link.
_OFFSITE = "evil.example"
_REDIRECT_TARGETS = (
    ("basic", "https://evil.example/x"),
    ("basic", "//evil.example/x"),
    ("backslash", "/\\evil.example/x"),  # browsers read /\ as // (scheme-relative)
)


def _login_redirect(ctx, acct, target: str, where: str) -> Optional[requests.Response]:
    """Log ``acct`` in with ``next=target`` (query or form); the raw 3xx, unfollowed."""
    from urllib.parse import quote

    from ..shared import csrf

    sess = requests.Session()
    path = "/login" + (f"?next={quote(target, safe='')}" if where == "query" else "")
    ctx.get(sess, path)  # the login form seeds the CSRF token
    ctx._seed_csrf(sess, "/login")
    tok = ctx._csrf_for(sess)
    data = dict(_login_payload(acct))
    if where == "form":
        data["next"] = target
    if tok:
        data[csrf.CSRF_FIELD] = tok
    try:
        return sess.post(ctx._url(path), data=data, timeout=ctx.http_timeout, allow_redirects=False,
                         headers={h: tok for h in csrf.CSRF_HEADERS} if tok else None)
    except requests.RequestException:
        return None


def _offsite(ctx, r: Optional[requests.Response]) -> bool:
    """Whether the redirect lands on the attacker's host, resolved as a browser does:
    in http(s) URLs a "\\" counts as "/" (so /\\host is //host), while an encoded
    %5C stays a same-site path character."""
    from urllib.parse import urljoin, urlsplit

    if r is None or not (300 <= r.status_code < 400):
        return False
    loc = r.headers.get("Location", "").replace("\\", "/")
    return urlsplit(urljoin(ctx.base_url + "/", loc)).hostname == _OFFSITE


def _to_login(r: requests.Response) -> bool:
    from urllib.parse import urlsplit
    return urlsplit(r.headers.get("Location", "")).path.rstrip("/").endswith("/login")


def dynamic_open_redirect(check, ctx, cfg):
    try:
        return _open_redirect(check, ctx, cfg)
    finally:
        # Every probe login ended userB's earlier session in apps that keep one
        # session per user; hand later probes a freshly logged-in userB.
        # Swap only on a real login: a 429 or a re-rendered login form is not one.
        if ctx.userB is not None:
            fresh = requests.Session()
            r = ctx.post(fresh, "/login", _login_payload(ctx.userB))
            if r is not None and 200 <= r.status_code < 400 and not _looks_like_login_form(_body_text(r)):
                ctx.userB.session = fresh


def _open_redirect(check, ctx, cfg):
    acct = ctx.userB  # an existing account: logging in again needs no write
    if acct is None:
        acct = new_account(ctx, "redir", n=6, name="", pw_tag="Rd")
    control = _login_redirect(ctx, acct, "/posts", "form")
    if control is None or not (300 <= control.status_code < 400) \
            or not control.headers.get("Location", "").rstrip("/").endswith("/posts"):
        code = control.status_code if control is not None else None
        return _undecidable(check, cfg, f"로그인 후 next 이동 기능을 확인할 수 없음(next=/posts → {code})")
    hits: Dict[str, str] = {}
    redirected = False  # did any attack login actually log in and redirect
    codes: List = []
    for kind, target in _REDIRECT_TARGETS:
        for where in ("query", "form"):
            r = _login_redirect(ctx, acct, target, where)
            codes.append(getattr(r, "status_code", None))
            # A 3xx back to /login is a refused login (limiter, lockout), not a login.
            redirected = redirected or (r is not None and 300 <= r.status_code < 400
                                        and not _to_login(r))
            if _offsite(ctx, r) and kind not in hits:
                hits[kind] = f"{where} next={target!r} → {r.status_code} Location: {r.headers.get('Location')!r}"
    if "basic" in hits:
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=["로그인 후 next로 받은 외부 주소로 그대로 이동 → Open Redirect(피싱 링크에 악용)"],
                      evidence=[_snip(hits["basic"])])
    if "backslash" in hits:
        return result(check, cfg, score=cfg.get("score_backslash", 50), passed=False,
                      reasons=["외부 URL·//는 막았지만 /\\로 시작하는 주소는 통과 → 브라우저가 //로 해석해 외부로 이동"],
                      evidence=[_snip(hits["backslash"])])
    if not redirected:
        # Every attack login was refused. An app that rejects the whole login over a
        # bad `next` (400) defends; a limiter or lockout would also refuse the same
        # login with a safe `next`, so that control tells the two apart.
        again = _login_redirect(ctx, acct, "/posts", "form")
        if again is not None and 300 <= again.status_code < 400 \
                and again.headers.get("Location", "").rstrip("/").endswith("/posts"):
            return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                          evidence=[_snip(f"외부 next를 넣은 로그인은 모두 거부 {codes}, "
                                          f"같은 계정의 next=/posts 로그인은 {again.status_code}로 이동")])
        return _undecidable(check, cfg, "공격 로그인이 모두 거부되어 판정 불가")
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip("외부 URL·//·/\\ next 모두 앱 내부로만 이동")])


# ── private_post_access  (dynamic) — the spec's private posts are the author's only.
# The list hiding them is the feature itself (the contract asks for it); the other
# ways to a post (detail, search, the author's profile, the comment endpoint) are
# what an app forgets. A unique word that only the private post holds, read back by
# someone who is not its author, is the proof.
def _private_post_id(ctx, author, title: str, resp) -> Optional[str]:
    """The private post's id: from the create response, else a /posts/<id> link on
    the author's own list or profile page whose detail shows ``title``."""
    j = _json_or_none(resp)
    if isinstance(j, dict):
        for key in ("id", "post_id", "pk"):
            if record_id(j.get(key)) is not None:
                return str(j[key])
        if isinstance(j.get("post"), dict) and record_id(j["post"].get("id")) is not None:
            return str(j["post"]["id"])
    for m in re.findall(r"/posts/([^/\"'?#\s<>]+)", str(getattr(resp, "url", "") or "")):
        if record_id(m) is not None:
            return m
    pages = ["/posts"]
    if author.user_id is not None:
        pages.append(f"/users/{author.user_id}")
    for page in pages:
        for pid in post_ids(_body_text(ctx.get(author.session, page)))[:15]:
            if title in _body_text(ctx.get(author.session, f"/posts/{pid}")):
                return str(pid)
    return None


# ── idor_write  (dynamic) — another user must not edit or delete someone's post
# or comment (BOLA on writes; idor_profile and private_post_access cover reads).
_COMMENT_LINK = re.compile(r"""/comments/([^/"'?#\s<>]+)""")


def _comment_id(ctx, sess, pid, resp) -> Optional[Any]:
    j = _json_or_none(resp)
    if isinstance(j, dict):
        for obj in (j, j.get("comment")):
            if isinstance(obj, dict):
                for key in ("id", "comment_id"):
                    if record_id(obj.get(key)) is not None:
                        return obj[key]
    found = _COMMENT_LINK.findall(_body_text(ctx.get(sess, f"/posts/{pid}")))
    return found[-1] if found else None


def _edit(ctx, sess, path: str, data: Dict[str, Any]):
    """(response, method): PATCH, or PUT when the app has no PATCH route."""
    r = ctx.patch(sess, path, data)
    if r is None or r.status_code in (404, 405):
        r2 = ctx.put(sess, path, data)
        if r2 is not None:
            return r2, "PUT"
    return r, "PATCH"


def _code(r) -> Any:
    return getattr(r, "status_code", "무응답")


def dynamic_idor_write(check, ctx, cfg):
    owner = new_account(ctx, "own", login=True, pw_tag="Ow")
    other = new_account(ctx, "atk", login=True, pw_tag="At")
    if owner is None or other is None:
        return _undecidable(check, cfg, "가입·로그인 실패로 판정 불가")
    tag = uuid.uuid4().hex[:10]
    title, body = f"Owned {tag} b", f"owner body {tag}"
    pid = create_post_id(ctx, owner.session, title, body)
    if pid is None:
        return _undecidable(check, cfg, "글 작성 실패로 판정 불가")
    # An untouched post of the owner's matching the same search: used only when the
    # probed post's page keeps failing after the delete (see below).
    kept_title = f"Owned {tag} c"
    kept = create_post_id(ctx, owner.session, kept_title, f"kept body {tag}")
    note = f"owner comment {tag}"
    cr = ctx.post(owner.session, f"/posts/{pid}/comments", {"content": note})
    cid = _comment_id(ctx, owner.session, pid, cr) if cr is not None and cr.status_code < 400 else None
    blind: List[str] = []  # reads that never showed the post's state

    def shows_state(r) -> bool:
        """A page that is the post's state: 2xx/3xx, or 404/410 for a missing post.
        No answer, a 5xx under load (sqlite locked ~10s, measured), a 401/403/429
        from a limiter or WAF are not: they are asked again, then left undecided."""
        return r is not None and (r.status_code < 400 or r.status_code in (404, 410))

    def detail():
        """The post as anyone sees it; a read that never shows its state is recorded
        in ``blind`` and ends the probe: the write it follows is undecided."""
        path = f"/posts/{pid}"
        r = None
        for i in range(int(cfg.get("detail_retries", 3))):
            if i:
                time.sleep(float(cfg.get("retry_wait_seconds", 5)))
            r = ctx.get(requests.Session(), path)
            if shows_state(r):
                return r
        blind.append(f"GET {path} {_code(r)}")
        return r

    def page() -> str:
        r = detail()
        return _body_text(r) if shows_state(r) else ""

    def finish():
        if hits:
            return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                          reasons=[f"{hits[0]} → 다른 사용자가 남의 글·댓글을 고치거나 지움"],
                          evidence=[_snip("; ".join(hits))])
        if blind:
            return _undecidable(check, cfg, f"글 상세를 읽지 못해 판정 불가, {blind[0]}")
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                      evidence=[_snip(f"다른 사용자의 {', '.join(tried)} → 글과 댓글 그대로")])

    if title not in page():
        return _undecidable(check, cfg, "작성한 글이 상세에 보이지 않아 판정 불가")
    hits: List[str] = []
    tried: List[str] = []
    forged = f"hacked {tag}"
    if cid is not None and note in page():
        r, how = _edit(ctx, other.session, f"/comments/{cid}", {"content": forged})
        tried.append(f"댓글 수정 {_code(r)}")
        if forged in page():
            hits.append(f"남의 댓글 수정 {how} /comments/{cid} → {_code(r)}")
        if blind:
            return finish()  # the app stopped answering: further writes prove nothing
        r = ctx.delete(other.session, f"/comments/{cid}")
        tried.append(f"댓글 삭제 {_code(r)}")
        text = page()
        if note not in text and forged not in text and title in text:
            hits.append(f"남의 댓글 삭제 DELETE /comments/{cid} → {_code(r)}")
    if blind:
        return finish()
    r, how = _edit(ctx, other.session, f"/posts/{pid}", {**_post_payload(forged, forged)})
    tried.append(f"글 수정 {_code(r)}")
    if forged in page():
        hits.append(f"남의 글 수정 {how} /posts/{pid} → {_code(r)}")
    if blind:
        return finish()
    r = ctx.delete(other.session, f"/posts/{pid}")
    tried.append(f"글 삭제 {_code(r)}")
    deleted = f"남의 글 삭제 DELETE /posts/{pid} → {_code(r)}"
    gone = detail()
    text = _body_text(gone) if shows_state(gone) else ""
    if shows_state(gone) and gone.status_code in (404, 410):
        hits.append(deleted)
    elif not (title in text or forged in text):
        # No 404, and no post on the page: it fails since the delete, or answers
        # without the post (a crash on a missing row, a 200 "too many requests"
        # page, a redirect to the list). Neither proves anything alone. Search (a
        # contract requirement) reads the same table and matches both posts in any
        # order: the probed post found means it is still there; only the untouched
        # one found means it is gone.
        sr = ctx.get(requests.Session(), f"/search?q=Owned%20{tag}")
        found = _body_text(sr) if sr is not None and sr.status_code < 400 else ""
        settled = title in found or (kept is not None and kept_title in found)
        if not shows_state(gone) and settled:
            blind.pop()  # the failed read of ``gone``: the search answered instead
        elif shows_state(gone) and not settled:
            blind.append(f"GET /posts/{pid} {_code(gone)}, 글이 보이지 않음")
        if settled and title not in found:
            hits.append(f"{deleted}, 이후 상세 {_code(gone)}, 검색에서 사라짐")
    return finish()


def dynamic_private_post_access(check, ctx, cfg):
    author = new_account(ctx, "prv", login=True, pw_tag="Pv")
    other = new_account(ctx, "peek", login=True, pw_tag="Pk")
    if author is None or other is None:
        return _undecidable(check, cfg, "가입·로그인 실패로 판정 불가")
    author.user_id = _discover_user_id(ctx, author)
    tag = uuid.uuid4().hex
    word, secret = "pq" + tag[:10], "zx" + tag[10:22]  # search term / leak proof
    title = f"Private {secret}"
    resp = ctx.post(author.session, "/posts",
                    {**_post_payload(title, f"{word} body {secret}"), "is_private": True})
    if resp is None or resp.status_code not in (200, 201):
        return _undecidable(check, cfg, f"비공개 글 작성 실패({getattr(resp, 'status_code', '무응답')})")
    pid = _private_post_id(ctx, author, title, resp)
    if pid is None:
        return _undecidable(check, cfg, "비공개 글의 id를 찾지 못함")
    if secret not in _body_text(ctx.get(author.session, f"/posts/{pid}")):
        return _undecidable(check, cfg, "작성자도 비공개 글 상세를 볼 수 없어 판정 불가")
    lst = ctx.get(requests.Session(), "/posts")
    if lst is None or lst.status_code >= 500:
        return _undecidable(check, cfg, "글 목록에 응답이 없어 판정 불가")
    if secret in _body_text(lst):
        return _undecidable(check, cfg, "비공개 글이 공개 목록에 보여 비공개 기능이 없음")

    probes = [("GET", f"/posts/{pid}"), ("GET", f"/search?q={word}"),
              ("GET", "/posts?sort=oldest"), ("GET", "/posts?sort=title")]
    if author.user_id is not None:
        probes.append(("GET", f"/users/{author.user_id}"))
    probes.append(("POST", f"/posts/{pid}/comments"))
    leaks: List[str] = []
    answered = 0
    for who, sess in (("로그인 안 한 사용자", requests.Session()), ("다른 사용자", other.session)):
        for method, path in probes:
            if method == "GET":
                r = ctx.get(sess, path)
            else:
                r = ctx.post(sess, path, {"content": f"peek {uuid.uuid4().hex[:6]}"})
            if r is None:
                continue
            answered += 1
            if secret in _body_text(r):
                leaks.append(f"{who} {method} {path} -> {r.status_code}")
    if leaks:
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=[f"{leaks[0]} → 작성자가 아닌 사람이 비공개 글을 읽음"],
                      evidence=[_snip("; ".join(leaks))])
    if answered == 0:
        return _undecidable(check, cfg, "요청에 응답이 없어 판정 불가")
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip(f"비공개 글 {pid}: 상세·검색·정렬 목록·프로필·댓글 {answered}건 모두 내용 없음")])


CHECKS = [
    Check("private_post_access", "비공개 글 접근 통제", "dynamic", dynamic_private_post_access),
    Check("csrf_protection", "CSRF 보호", "dynamic", dynamic_csrf_protection),
    Check("ssrf", "SSRF", "dynamic", dynamic_ssrf),
    Check("idor_profile", "IDOR", "dynamic", dynamic_idor_profile),
    Check("idor_write", "남의 글·댓글 수정 삭제", "dynamic", dynamic_idor_write),
    Check("access_control_admin", "관리자 페이지 접근 통제", "dynamic",
          dynamic_access_control_admin),
    Check("privilege_escalation", "Mass Assignment", "dynamic",
          dynamic_privilege_escalation),
    Check("admin_user_mgmt", "관리자 역할 변경 인가", "dynamic",
          dynamic_admin_user_mgmt),
    Check("open_redirect", "Open Redirect", "dynamic", dynamic_open_redirect),
]
