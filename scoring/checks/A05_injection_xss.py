"""A05 Injection (XSS): the template-escaping and CSP static checks, plus the
stored and reflected XSS probes.
"""
from __future__ import annotations

import re
import uuid
from typing import List, Optional, Tuple

import requests

from ..shared.http import (
    _body_text, _is_html_response, _post_payload, _snip, create_post_id,
)
from ..shared.sources import _balanced_arg, _joined
from .base import Check, _undecidable, result


# ── xss_template  (static) ─────────────────────────────────────────────────
_RENDER_STR = re.compile(r"""render_template_string\s*\(""")
_SAFE_FILTER = re.compile(r"""\|\s*safe""")
_AUTOESCAPE_OFF = re.compile(r"""autoescape\s*=\s*False""", re.IGNORECASE)
_REQUEST_DATA = re.compile(r"""request\.|\bg\.|session\[""")
# {{ x | safe }} disables autoescape. Three carve-outs keep this from false-flagging:
#  1) the common SAFE helpers (url_for/csrf/config/url values) — marking those safe is fine;
#  2) a built-in escape filter BEFORE |safe — {{ x | e | replace('\n','<br>') | safe }} is the
#     safe nl2br idiom: the value is HTML-escaped first, so |safe re-marks already-safe text;
#  3) a CUSTOM filter BEFORE |safe whose Python definition escapes — e.g. a filter
#     `escape_content` = Markup("<br>".join(escape(v).splitlines())): {{ c | escape_content | safe }}
#     is the same idiom via a named filter. Only filters whose body actually escapes count.
# A raw {{ post.content | safe }} (no escape before it) is still flagged.
_BRACE_BLOCK = re.compile(r"""\{\{.*?\}\}""", re.DOTALL)
_SAFE_IN_BLOCK = re.compile(r"""\|\s*safe\b""", re.IGNORECASE)
_ESCAPE_FILTER = re.compile(r"""\|\s*(?:e|escape|forceescape)\b""", re.IGNORECASE)
_SAFE_HELPERS = re.compile(r"""url_for|csrf|url_encode|tojson|config\.|\bg\.""", re.IGNORECASE)
_TPL_AUTOESCAPE_OFF = re.compile(r"""\{%\s*autoescape\s+false\s*%\}""", re.IGNORECASE)

# Custom-filter registration → the implementing function; and what "escapes" looks like.
_FILTER_DECORATOR = re.compile(
    r"""@\w+\.(?:template_filter|app_template_filter)\s*\(\s*(?:['"](?P<name>[^'"]+)['"])?\s*\)\s*\r?\n\s*def\s+(?P<fn>\w+)""",
)
_FILTER_ASSIGN = re.compile(
    r"""\.filters\s*\[\s*['"](?P<name>[^'"]+)['"]\s*\]\s*=\s*(?P<fn>\w+)""",
)
# Flask's app.add_template_filter(fn, "name") / add_template_filter(fn) (name defaults
# to the function name).
_FILTER_ADD = re.compile(
    r"""\.add_template_filter\s*\(\s*(?P<fn>\w+)\s*(?:,\s*(?:name\s*=\s*)?['"](?P<name>[^'"]+)['"])?""",
)
_ESCAPES_IN_BODY = re.compile(
    r"""\bescape\s*\(|markupsafe|bleach\.clean|\.clean\s*\(|escape_silent""", re.IGNORECASE,
)


def _func_escapes(text: str, fn: str) -> bool:
    """Does the module-level function ``fn`` HTML-escape in its body? Body = from its
    ``def`` to the next top-level ``def``/EOF."""
    m = re.search(r"^\s*def\s+" + re.escape(fn) + r"\b", text, re.MULTILINE)
    if not m:
        return False
    rest = text[m.end():]
    nxt = re.search(r"^def\s", rest, re.MULTILINE)
    body = rest[:nxt.start()] if nxt else rest
    return _ESCAPES_IN_BODY.search(body) is not None


def _escaping_filter_names(sources) -> set:
    """Names of custom Jinja filters whose implementation escapes — so `| name | safe`
    is the safe escape-then-mark idiom, not a bypass."""
    names = set()
    for _path, text in sources:
        for m in _FILTER_DECORATOR.finditer(text):
            fn = m.group("fn")
            if _func_escapes(text, fn):
                names.add(m.group("name") or fn)
        for m in _FILTER_ASSIGN.finditer(text):
            if _func_escapes(text, m.group("fn")):
                names.add(m.group("name"))
        for m in _FILTER_ADD.finditer(text):
            fn = m.group("fn")
            if _func_escapes(text, fn):
                names.add(m.group("name") or fn)
    return names


def _block_bypasses_escape(block: str, escaping_filters=()) -> bool:
    """True only when a {{ ... }} block marks a value ``|safe`` WITHOUT escaping it
    first (real autoescape bypass). Escape-before-safe (built-in or a known escaping
    custom filter) and the SAFE helpers are not."""
    m = _SAFE_IN_BLOCK.search(block)
    if not m:
        return False
    if _SAFE_HELPERS.search(block):
        return False
    before = block[:m.start()]
    if _ESCAPE_FILTER.search(before):
        return False
    for nm in escaping_filters:
        if re.search(r"\|\s*" + re.escape(nm) + r"\b", before):
            return False
    return True


def check_xss_template(check, sctx, cfg):
    penalty = float(cfg.get("penalty_per_finding", 35))
    score_clean = float(cfg.get("score_clean", 100))

    reasons: List[str] = []
    evidence: List[str] = []
    escaping_filters = _escaping_filter_names(sctx.sources)

    for path, text in sctx.sources:
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

    for path, text in sctx.templates:
        for i, line in enumerate(text.splitlines(), start=1):
            if any(_block_bypasses_escape(b.group(0), escaping_filters) for b in _BRACE_BLOCK.finditer(line)):
                reasons.append(f"{path}:{i} |safe 필터로 자동 이스케이프 우회")
                evidence.append(f"{path}:{i}: {line.strip()}")
            if _TPL_AUTOESCAPE_OFF.search(line):
                reasons.append(f"{path}:{i} autoescape false 블록으로 이스케이프 비활성화")
                evidence.append(f"{path}:{i}: {line.strip()}")

    return result(check, cfg, score=score_clean - penalty * len(reasons),
                  passed=not reasons, reasons=reasons, evidence=evidence)


# ── csp  (static) — CSP as XSS defense-in-depth. autoescape is the Jinja default
# (free); a CSP constraining script sources must be actively set. Look in source
# (response headers / Talisman / flask-seasurf-style) and template meta tags.
_CSP_MARKERS = re.compile(
    r"""Content-Security-Policy|content_security_policy|["']CSP["']|Talisman\s*\(|"""
    r"""http-equiv\s*=\s*["']Content-Security-Policy["']""",
    re.IGNORECASE,
)


def check_csp(check, sctx, cfg):
    haystack = _joined(sctx.sources) + "\n" + _joined(sctx.templates)
    hit = _CSP_MARKERS.search(haystack)
    if hit:
        return result(check, cfg, score=cfg.get("score_present", 100), passed=True,
                      evidence=[hit.group(0)])
    return result(check, cfg, score=cfg.get("score_missing", 0), passed=False,
                  reasons=["Content-Security-Policy 미설정 → 자동escape 우회(속성/JS 컨텍스트) XSS에 무방비. "
                           "autoescape는 프레임워크 기본값일 뿐 CSP로 스크립트 출처를 제한해야 함"])


# ── stored_xss  (dynamic, multi-payload, multi-context) ────────────────────
def dynamic_stored_xss(check, ctx, cfg):
    if ctx.userA is None:
        return _undecidable(check, cfg, "작성자 세션 없음으로 XSS 판정 불가")

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
    for path in ("/posts", (f"/users/{ctx.userA.user_id}" if ctx.userA.user_id else None)):
        if not path:
            continue
        resp = ctx.get(sess, path, headers={"Accept": "text/html"})
        if not _is_html_response(resp):
            continue  # JSON data response: a raw payload here is not XSS
        body = _body_text(resp)
        hit = _find_unescaped(body, variants)
        if hit:
            _marker, sig = hit
            at = body.find(sig)
            return result(check, cfg, score=cfg.get("score_stored_unescaped", 0), passed=False,
                          reasons=[f"{path} 렌더에 XSS 페이로드가 이스케이프 없이 노출됨 → 저장형 XSS (payload={sig!r})"],
                          evidence=[_snip(f"{path}: …{body[max(0, at - 40): at + 100]}…")])

    # Post-detail sink: rich-text / markdown rendering usually happens on the detail
    # page (/posts/<id>), not the list — an app can escape the list yet render the body
    # raw there (|safe, render_template_string, unsanitized markdown). Store every
    # payload in one body and read it back on detail.
    combined = " ".join(p for _m, p, _s in variants)
    dpid = create_post_id(ctx, sess, "xssd-" + uuid.uuid4().hex[:8], combined)
    if dpid is not None:
        detail = ctx.get(sess, f"/posts/{dpid}", headers={"Accept": "text/html"})
        if _is_html_response(detail):
            dbody = _body_text(detail)
            dhit = _find_unescaped(dbody, variants)
            if dhit:
                _dm, dsig = dhit
                at = dbody.find(dsig)
                return result(check, cfg, score=cfg.get("score_stored_unescaped", 0), passed=False,
                              reasons=[f"/posts/{dpid} 상세 본문 렌더에 XSS 페이로드가 이스케이프 없이 노출 → 저장형 XSS (payload={dsig!r})"],
                              evidence=[_snip(f"/posts/{dpid}: …{dbody[max(0, at - 40): at + 100]}…")])

    # Comment sink: comments are a second stored-XSS surface — an app can escape
    # post bodies yet forget comments. Needs a post id; skip the pass if unavailable.
    pid = create_post_id(ctx, sess, "xssc-" + uuid.uuid4().hex[:8], "xssc-" + uuid.uuid4().hex[:8])
    if pid is not None:
        for _m, payload, _s in variants:
            ctx.post(sess, f"/posts/{pid}/comments", {"content": payload, "body": payload})
        detail = ctx.get(sess, f"/posts/{pid}", headers={"Accept": "text/html"})
        if _is_html_response(detail):
            cbody = _body_text(detail)
            chit = _find_unescaped(cbody, variants)
            if chit:
                _cm, csig = chit
                at = cbody.find(csig)
                return result(check, cfg, score=cfg.get("score_stored_unescaped", 0), passed=False,
                              reasons=[f"/posts/{pid} 댓글 렌더에 XSS 페이로드가 이스케이프 없이 노출 → 저장형 XSS(댓글) (payload={csig!r})"],
                              evidence=[_snip(f"/posts/{pid} 댓글: …{cbody[max(0, at - 40): at + 100]}…")])

    note = "입력이 거부되어 저장 안됨" if rejected else "저장되었으나 출력 시 이스케이프됨"
    return result(check, cfg, score=cfg.get("score_escaped_or_rejected", 100), passed=True,
                  evidence=[_snip(f"XSS 방어됨 ({note}); {len(variants)}종 페이로드 검증")])


# ── reflected_xss  (dynamic) — payload echoed back in /search or error pages.
def dynamic_reflected_xss(check, ctx, cfg):
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
                return result(check, cfg, score=cfg.get("score_reflected", 0), passed=False,
                              reasons=[f"{path} 응답에 입력 페이로드가 이스케이프 없이 반사됨 → 반사형 XSS (payload={sig!r})"],
                              evidence=[_snip(f"{path}: …{body[max(0, at - 40): at + 100]}…")])
    return result(check, cfg, score=cfg.get("score_clean", 100), passed=True,
                  evidence=[_snip(f"반사형 XSS 미검출; {len(variants)}종 페이로드 검증")])


# A payload is "unescaped" if its dangerous raw fragment survives verbatim in the
# rendered HTML (the app neither escaped <>&" nor rejected it).
def _xss_variants(ctx) -> List[Tuple[str, str, str]]:
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


CHECKS = [
    Check("xss_template", "XSS 템플릿", "static", check_xss_template),
    Check("csp", "CSP(XSS 심층방어)", "static", check_csp),
    Check("stored_xss", "저장형 XSS", "dynamic", dynamic_stored_xss),
    Check("reflected_xss", "반사형 XSS", "dynamic", dynamic_reflected_xss),
]
