"""A01 Broken Access Control (SSRF folded in for 2025): CSRF protection and SSRF
sink static checks, plus the IDOR and admin access-control probes.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence

from ..models import CheckResult
from ..shared.http import (
    Account, ProbeContext, _body_text, _json_or_none, _looks_like_admin, _low_conf, _snip,
)
from ..shared.sources import Source, _joined, _mk
from .base import Control


# CSRF protection. State-changing POST forms need a token / Flask-WTF.
_CSRF_MARKERS = re.compile(
    r"""csrf_token|CSRFProtect|flask_wtf|WTF_CSRF|csrf\.protect|X-CSRF|csrf_protect""",
    re.IGNORECASE,
)


def check_csrf_protection(
    sources: Sequence[Source], cfg: dict,
    templates: Optional[Sequence[Source]] = None,
) -> CheckResult:
    haystack = _joined(sources) + "\n" + _joined(templates or [])
    hit = _CSRF_MARKERS.search(haystack)
    if hit:
        return _mk("csrf_protection", "CSRF 보호", float(cfg.get("score_protected", 100)),
                   cfg, passed=True, reasons=[], evidence=[hit.group(0)])
    return _mk("csrf_protection", "CSRF 보호", float(cfg.get("score_missing", 0)),
               cfg, passed=False,
               reasons=["폼/요청에 CSRF 토큰·Flask-WTF 등 CSRF 방어가 없음 → 상태변경 요청 위조 가능"],
               evidence=[])


# SSRF sink (folded into Broken Access Control for 2025). Outbound fetch with a non-literal (possibly user) URL.
_OUTBOUND = re.compile(
    r"""(?:requests\.(?:get|post|put|delete|head|request)|httpx\.(?:get|post)|urllib\.request\.urlopen|urlopen)\s*\(\s*(?P<arg>[^,)\s]+)""",
    re.IGNORECASE,
)


def check_ssrf_sink(sources: Sequence[Source], cfg: dict) -> CheckResult:
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sources:
        for m in _OUTBOUND.finditer(text):
            arg = m.group("arg").strip()
            if arg[:1] in ("'", '"'):
                continue  # literal/constant URL => not user-controlled
            lineno = text.count("\n", 0, m.start()) + 1
            reasons.append(f"{path}:{lineno} 사용자 제어 가능 URL로 외부 요청 → SSRF 가능: {arg}")
            evidence.append(f"{path}:{lineno}: {m.group(0)[:120]}")
    if reasons:
        return _mk("ssrf_sink", "SSRF", float(cfg.get("score_sink", 0)), cfg,
                   passed=False, reasons=reasons, evidence=evidence)
    # No outbound sink at all is the common (safe) case for a board app.
    return _mk("ssrf_sink", "SSRF", float(cfg.get("score_no_sink", 100)), cfg,
               passed=True, reasons=[], evidence=[])


# idor_profile (dynamic)
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


# access_control_admin (dynamic)
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


CONTROLS = [
    Control("csrf_protection", "CSRF 보호", "static",
            lambda sctx, cfg: check_csrf_protection(sctx.sources, cfg, sctx.templates)),
    Control("ssrf_sink", "SSRF", "static",
            lambda sctx, cfg: check_ssrf_sink(sctx.sources, cfg)),
    Control("idor_profile", "IDOR(타인 프로필 조회)", "dynamic", probe_idor_profile),
    Control("access_control_admin", "접근 통제(관리자 페이지)", "dynamic", probe_access_control_admin),
]
