"""A01 Broken Access Check (SSRF folded in for 2025): CSRF protection and SSRF
sink static checks, plus the IDOR and admin access-control probes.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional

import requests

from ..shared.http import (
    _body_text, _json_or_none, _looks_like_admin, _post_payload, _snip, create_post_id,
)
from ..shared.sources import _joined
from .base import Check, _undecidable, result


# ── csrf_protection  (static) — state-changing POST forms need a token/Flask-WTF.
_CSRF_MARKERS = re.compile(
    r"""csrf_token|CSRFProtect|flask_wtf|WTF_CSRF|csrf\.protect|X-CSRF|csrf_protect""",
    re.IGNORECASE,
)
# SameSite=Lax/Strict cookies aren't sent on cross-site POSTs, so they block the
# classic CSRF (attacker-page form → victim app) even without an explicit token.
_SAMESITE_CSRF = re.compile(
    r"""(?:SESSION_COOKIE_SAMESITE["'\]\s]*[=:]\s*|samesite\s*=\s*)["'](?:Lax|Strict)["']""",
    re.IGNORECASE,
)


def check_csrf_protection(check, sctx, cfg):
    haystack = _joined(sctx.sources) + "\n" + _joined(sctx.templates)
    hit = _CSRF_MARKERS.search(haystack) or _SAMESITE_CSRF.search(haystack)
    if hit:
        return result(check, cfg, score=cfg.get("score_protected", 100), passed=True,
                      evidence=[hit.group(0)])
    return result(check, cfg, score=cfg.get("score_missing", 0), passed=False,
                  reasons=["CSRF 토큰·Flask-WTF도, SameSite=Lax/Strict 쿠키도 없음 → 상태변경 요청 위조 가능"])


# ── ssrf_sink  (static) — outbound fetch with a non-literal (possibly user) URL.
_OUTBOUND = re.compile(
    r"""(?:requests\.(?:get|post|put|delete|head|request)|httpx\.(?:get|post)|urllib\.request\.urlopen|urlopen)\s*\(\s*(?P<arg>[^,)\s]+)""",
    re.IGNORECASE,
)


def check_ssrf_sink(check, sctx, cfg):
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sctx.sources:
        for m in _OUTBOUND.finditer(text):
            arg = m.group("arg").strip()
            if arg[:1] in ("'", '"'):
                continue  # literal/constant URL => not user-controlled
            if re.fullmatch(r"[A-Z_][A-Z0-9_]*", arg):
                continue  # ALL_CAPS module constant (e.g. API_URL) => not user input
            lineno = text.count("\n", 0, m.start()) + 1
            reasons.append(f"{path}:{lineno} 사용자 제어 가능 URL로 외부 요청 → SSRF 가능: {arg}")
            evidence.append(f"{path}:{lineno}: {m.group(0)[:120]}")
    if reasons:
        return result(check, cfg, score=cfg.get("score_sink", 0), passed=False,
                      reasons=reasons, evidence=evidence)
    # No outbound sink at all is the common (safe) case for a board app.
    return result(check, cfg, score=cfg.get("score_no_sink", 100), passed=True)


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
        return result(check, cfg, score=cfg.get("score_control_broken", 60), passed=False,
                      reasons=["본인 전화번호도 조회되지 않아 접근 통제 확인 불가(control broken)"],
                      evidence=evidence)
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
        if last_code == 200 and phone and phone in _digits(last_body):
            return True, last_code, last_body
    return False, last_code, last_body


def _discover_user_id(ctx, acct) -> Optional[int]:
    """If login didn't return an id, probe /users/<n> with the account's own
    session and match its phone (digit-robust, HTML+JSON) to find its id."""
    if acct is None or not acct.phone:
        return None
    phone = _digits(acct.phone)
    for uid in range(1, 11):
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

    # Admin account must still reach admin (if required) before we credit concealment.
    require_admin = bool(cfg.get("require_admin_control", True))
    admin_control_ok = _admin_reaches_admin(ctx) if (require_admin and ctx.admin is not None) else True

    if exposed_paths:
        reasons = [f"일반 사용자(userB) 세션으로 {p} 노출됨 → 접근 통제 실패" for p in exposed_paths]
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=reasons, evidence=evidence)

    # All blocked. Award 404 concealment only if admin control still works.
    both_404 = all(codes.get(p) == 404 for p in ("/admin", "/admin/users"))
    if both_404:
        if require_admin and not admin_control_ok:
            return result(check, cfg, score=cfg.get("score_403", 90), passed=True,
                          reasons=["관리자 페이지가 관리자 계정에서도 도달 불가 — 은닉 보너스는 유보"],
                          evidence=evidence)
        return result(check, cfg, score=cfg.get("score_404", 100), passed=True, evidence=evidence)
    # Blocked (403/redirect/other non-exposing) => defended.
    return result(check, cfg, score=cfg.get("score_403", 90), passed=True, evidence=evidence)


def _admin_reaches_admin(ctx) -> bool:
    ra = ctx.get(ctx.admin.session, "/admin")
    ru = ctx.get(ctx.admin.session, "/admin/users")
    return any(
        r is not None and r.status_code == 200 and _looks_like_admin(_body_text(r), _json_or_none(r))
        for r in (ra, ru)
    )


# ── privilege_escalation  (dynamic) — mass assignment: does /signup trust a
# client-supplied is_admin/role field?
_PRIVESC_FIELDS = {"is_admin": True, "admin": True, "role": "admin", "is_staff": True}


def dynamic_privilege_escalation(check, ctx, cfg):
    """PoC: sign up while sending is_admin/role in the body. If that account reaches
    the admin area while a plain-signup control does not, the app trusted a
    client-set privilege field (mass assignment)."""
    extra = dict(cfg.get("admin_fields") or _PRIVESC_FIELDS)
    attacker = _signup_login(ctx, extra)
    control = _signup_login(ctx, {})
    if attacker is None or control is None:
        return _undecidable(check, cfg, "가입/로그인 실패로 권한상승 판정 불가")

    if _reaches_admin(ctx, control) is not None:
        # Admin area is open to ANY signup — that is access_control_admin's finding.
        return _undecidable(check, cfg,
                            "관리자 페이지가 일반 가입자에게도 열려 mass-assignment로 분리 판정 불가")

    atk_path = _reaches_admin(ctx, attacker)
    if atk_path is not None:
        return result(check, cfg, score=cfg.get("score_escalated", 0), passed=False,
                      reasons=[f"가입 요청의 {sorted(extra)} 필드를 신뢰 → 관리자 권한 탈취({atk_path})"],
                      evidence=[_snip(f"is_admin 포함 가입 → GET {atk_path} 관리자 콘텐츠 노출 / 대조군(일반 가입)은 차단")])
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip("is_admin 주입 가입도 관리자 접근 불가 → mass-assignment 방어됨")])


def _signup_login(ctx, extra: Dict[str, Any]) -> Optional[requests.Session]:
    sess = requests.Session()
    tag = uuid.uuid4().hex[:10]
    creds = {"username": f"pe_{tag}", "phone": "010" + tag[:8].translate(str.maketrans("abcdef", "012345")),
             "name": f"pe_{tag}", "password": "Booth!Secure2345"}
    su = ctx.post(sess, "/signup", {**creds, **extra})
    if su is None or su.status_code not in (200, 201, 409):
        return None
    ctx.post(sess, "/login", {"username": creds["username"], "phone": creds["phone"],
                              "password": creds["password"]})
    return sess


def _reaches_admin(ctx, sess: requests.Session) -> Optional[str]:
    for path in ("/admin", "/admin/users"):
        r = ctx.get(sess, path)
        if r is not None and r.status_code == 200 and _looks_like_admin(_body_text(r), _json_or_none(r)):
            return path
    return None


# ── object_authorization  (dynamic) — BOLA: can userB modify userA's post? ──
def dynamic_object_authorization(check, ctx, cfg):
    """userA writes a post; userA can edit it (positive control); userB must NOT.
    A userB edit/delete that LANDS (verified by a fresh GET of the object, never
    the write response) is broken object-level authorization."""
    if ctx.userA is None or ctx.userB is None:
        return _undecidable(check, cfg, "테스트 계정 부족으로 객체 인가 판정 불가")

    tag = "bola-" + uuid.uuid4().hex[:10]
    pid = create_post_id(ctx, ctx.userA.session, tag, tag)
    if pid is None:
        return _undecidable(check, cfg, "userA 글 생성/식별 실패로 판정 불가")

    # Positive control: the owner can edit their own post. If not, the edit feature
    # is absent/broken and we cannot fairly test the attacker — skip, don't accuse.
    if not _edit_lands(ctx, ctx.userA.session, pid):
        return _undecidable(check, cfg, "작성자 본인도 수정이 안 돼 판정 불가(수정 기능 없음/실패)")

    attacker_text = "bola-atk-" + uuid.uuid4().hex[:8]
    if _edit_lands(ctx, ctx.userB.session, pid, attacker_text):
        return result(check, cfg, score=cfg.get("score_broken", 0), passed=False,
                      reasons=[f"userB가 userA 글(id={pid})을 수정 → 객체 수준 인가 실패(BOLA)"],
                      evidence=[_snip(f"userB PUT /posts/{pid} → 이후 GET에 공격자 내용 반영")])

    if _delete_lands(ctx, ctx.userB.session, pid):
        return result(check, cfg, score=cfg.get("score_broken", 0), passed=False,
                      reasons=[f"userB가 userA 글(id={pid})을 삭제 → 객체 수준 인가 실패(BOLA)"],
                      evidence=[_snip(f"userB DELETE /posts/{pid} → 글이 사라짐(404)")])

    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip(f"userB의 글 {pid} 수정·삭제 시도 모두 차단됨")])


def _edit_lands(ctx, sess, pid: int, new_text: Optional[str] = None) -> bool:
    """PUT/PATCH the post, then confirm the change on a FRESH GET of the object
    (not the write response — a rejected write may still echo the input)."""
    new_text = new_text or ("owner-edit-" + uuid.uuid4().hex[:8])
    payload = _post_payload(f"bola-edit-{new_text}", new_text)
    for verb in (ctx.put, ctx.patch):
        r = verb(sess, f"/posts/{pid}", payload)
        if r is None or r.status_code >= 500:
            continue
        if new_text in _body_text(ctx.get(sess, f"/posts/{pid}")):
            return True
    return False


def _delete_lands(ctx, sess, pid: int) -> bool:
    """DELETE the post, judged solely by the object 404-ing afterward (a strong,
    low-false-positive signal); a soft-delete that keeps 200 counts as blocked."""
    before = ctx.get(sess, f"/posts/{pid}")
    if before is None or before.status_code == 404:
        return False
    if ctx.delete(sess, f"/posts/{pid}") is None:
        return False
    after = ctx.get(sess, f"/posts/{pid}")
    return after is not None and after.status_code == 404


# ── admin_user_mgmt  (dynamic) — a normal user must not run admin user-management.
def dynamic_admin_user_mgmt(check, ctx, cfg):
    """PoC: userB calls the role-change endpoint on ITSELF, then checks whether it
    now reaches /admin. Effect-based (an actual self-promotion), so a soft-deny 200
    from the endpoint isn't a false hit. Non-destructive — touches no other account."""
    if ctx.userB is None:
        return _undecidable(check, cfg, "일반 사용자 세션 없음으로 판정 불가")
    # If the admin area is already open to any user, that is access_control_admin's
    # finding — don't double-judge (would double-penalize the same defect).
    if _reaches_admin(ctx, ctx.userB.session) is not None:
        return _undecidable(check, cfg, "관리자 페이지가 일반 사용자에게 이미 열려 별도 판정 불가")

    uid = ctx.userB.user_id or _discover_user_id(ctx, ctx.userB)
    if uid is None:
        return _undecidable(check, cfg, "userB id 확인 불가로 판정 불가")

    ctx.post(ctx.userB.session, f"/admin/users/{uid}/role", {"role": "admin", "is_admin": True})
    reached = _reaches_admin(ctx, ctx.userB.session)
    if reached is not None:
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=[f"userB가 /admin/users/{uid}/role 로 스스로 관리자 승격 → 관리자 사용자관리 인가 실패"],
                      evidence=[_snip(f"일반 사용자 역할변경 후 {reached} 관리자 접근 획득")])
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip("일반 사용자의 역할 변경 시도가 관리자 권한으로 이어지지 않음")])


CHECKS = [
    Check("csrf_protection", "CSRF 보호", "static", check_csrf_protection),
    Check("ssrf_sink", "SSRF", "static", check_ssrf_sink),
    Check("idor_profile", "IDOR(타인 프로필 조회)", "dynamic", dynamic_idor_profile),
    Check("access_control_admin", "접근 통제(관리자 페이지)", "dynamic",
          dynamic_access_control_admin),
    Check("privilege_escalation", "권한 상승(mass-assignment)", "dynamic",
          dynamic_privilege_escalation),
    Check("object_authorization", "객체 인가(BOLA·글 수정/삭제)", "dynamic",
          dynamic_object_authorization),
    Check("admin_user_mgmt", "관리자 사용자관리 인가", "dynamic",
          dynamic_admin_user_mgmt),
]
