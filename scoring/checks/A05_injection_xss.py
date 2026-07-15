"""A05 Injection (XSS): the template-escaping and CSP static checks, plus the
stored and reflected XSS probes.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

from ..models import CheckResult
from ..shared.http import (
    DynamicContext, _body_text, _is_html_response, _scored_zero, _post_payload, _snip,
)
from ..shared.sources import Source, _balanced_arg, _clamp, _joined, _mk
from .base import Check


# xss_template
_RENDER_STR = re.compile(r"""render_template_string\s*\(""")
_SAFE_FILTER = re.compile(r"""\|\s*safe""")
_AUTOESCAPE_OFF = re.compile(r"""autoescape\s*=\s*False""", re.IGNORECASE)
_REQUEST_DATA = re.compile(r"""request\.|\bg\.|session\[""")
_TPL_SAFE = re.compile(r"""\{\{[^}]*\|\s*safe[^}]*\}\}""")
_TPL_AUTOESCAPE_OFF = re.compile(r"""\{%\s*autoescape\s+false\s*%\}""", re.IGNORECASE)


def check_xss_template(
    sources: Sequence[Source],
    cfg: dict,
    templates: Optional[Sequence[Source]] = None,
) -> CheckResult:
    penalty = float(cfg.get("penalty_per_finding", 35))
    score_clean = float(cfg.get("score_clean", 100))

    reasons: List[str] = []
    evidence: List[str] = []

    for path, text in sources:
        for m in _RENDER_STR.finditer(text):
            open_idx = text.index("(", m.end() - 1)
            arg = _balanced_arg(text, open_idx)
            lineno = text.count("\n", 0, m.start()) + 1
            if _REQUEST_DATA.search(arg) or _SAFE_FILTER.search(arg):
                reasons.append(f"{path}:{lineno} render_template_string에 사용자 입력/`|safe` 사용")
                evidence.append(f"{path}:{lineno}: {arg.strip()[:160]}")
        for i, line in enumerate(text.splitlines(), start=1):
            if _SAFE_FILTER.search(line) and _RENDER_STR.search(line) is None:
                if not any(f"{path}:{i}" in r for r in reasons):
                    reasons.append(f"{path}:{i} 템플릿 문자열에서 `|safe` 필터 사용")
                    evidence.append(f"{path}:{i}: {line.strip()}")
            if _AUTOESCAPE_OFF.search(line):
                reasons.append(f"{path}:{i} autoescape=False 설정")
                evidence.append(f"{path}:{i}: {line.strip()}")

    for path, text in (templates or []):
        for i, line in enumerate(text.splitlines(), start=1):
            if _TPL_SAFE.search(line):
                reasons.append(f"{path}:{i} |safe 필터로 자동 이스케이프 우회")
                evidence.append(f"{path}:{i}: {line.strip()}")
            if _TPL_AUTOESCAPE_OFF.search(line):
                reasons.append(f"{path}:{i} autoescape false 블록으로 이스케이프 비활성화")
                evidence.append(f"{path}:{i}: {line.strip()}")

    score = _clamp(score_clean - penalty * len(reasons))
    return CheckResult(
        check_id="xss_template",
        category="static",
        label="XSS 템플릿",
        score=score,
        weight=float(cfg.get("weight", 0)),
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
    )


# CSP as XSS defense-in-depth. autoescape is the Jinja default (free); a CSP
# constraining script sources must be actively set. Look in source (response
# headers / Talisman / flask-seasurf-style) and template meta tags.
_CSP_MARKERS = re.compile(
    r"""Content-Security-Policy|content_security_policy|["']CSP["']|Talisman\s*\(|"""
    r"""http-equiv\s*=\s*["']Content-Security-Policy["']""",
    re.IGNORECASE,
)


def check_csp(
    sources: Sequence[Source], cfg: dict,
    templates: Optional[Sequence[Source]] = None,
) -> CheckResult:
    haystack = _joined(sources) + "\n" + _joined(templates or [])
    hit = _CSP_MARKERS.search(haystack)
    if hit:
        return _mk("csp", "CSP(XSS 심층방어)", float(cfg.get("score_present", 100)),
                   cfg, passed=True, reasons=[], evidence=[hit.group(0)])
    return _mk("csp", "CSP(XSS 심층방어)", float(cfg.get("score_missing", 0)),
               cfg, passed=False,
               reasons=["Content-Security-Policy 미설정 → 자동escape 우회(속성/JS 컨텍스트) XSS에 무방비. "
                        "autoescape는 프레임워크 기본값일 뿐 CSP로 스크립트 출처를 제한해야 함"],
               evidence=[])


# XSS helpers: a payload is "unescaped" if its dangerous raw fragment survives
# verbatim in the rendered HTML (the app neither escaped <>&" nor rejected it).
def _xss_variants(ctx: DynamicContext) -> List[Tuple[str, str, str]]:
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


# stored_xss (dynamic, multi-payload, multi-context)
def dynamic_stored_xss(ctx: DynamicContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 18))
    label = "저장형 XSS"
    try:
        if ctx.userA is None:
            return _scored_zero("stored_xss", label, weight, "작성자 세션 없음으로 XSS 판정 불가")

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
        return _scored_zero("stored_xss", label, weight, f"XSS 프로브 예외: {exc}")


# reflected_xss — payload echoed back in /search or error pages.
def dynamic_reflected_xss(ctx: DynamicContext, cfg: Dict[str, Any]) -> CheckResult:
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
        return _scored_zero("reflected_xss", label, weight, f"반사형 XSS 프로브 예외: {exc}")


CHECKS = [
    Check("xss_template", "XSS 템플릿", "static",
            lambda sctx, cfg: check_xss_template(sctx.sources, cfg, sctx.templates)),
    Check("csp", "CSP(XSS 심층방어)", "static",
            lambda sctx, cfg: check_csp(sctx.sources, cfg, sctx.templates)),
    Check("stored_xss", "저장형 XSS", "dynamic", dynamic_stored_xss),
    Check("reflected_xss", "반사형 XSS", "dynamic", dynamic_reflected_xss),
]
