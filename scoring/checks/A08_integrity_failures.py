"""A08 Software or Data Integrity Failures: insecure deserialization / dynamic
exec on request data (static check), plus the unrestricted-upload probe.
"""
from __future__ import annotations

import re
import uuid
from typing import List

import requests

from ..shared.http import _body_text, _json_or_none, _snip
from ..shared.sources import _balanced_arg
from .base import Check, _undecidable, result


# ── insecure_deserialization  (static) ─────────────────────────────────────
_INSECURE_DESER = re.compile(
    r"""pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)|(?<![\w.])(eval|exec)\s*\(""",
    re.IGNORECASE,
)
_REQUEST_NEAR = re.compile(r"""request\.|request\[""")


def check_insecure_deserialization(check: Check, sctx, cfg: dict):
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sctx.sources:
        lines = text.splitlines()
        for m in _INSECURE_DESER.finditer(text):
            token = m.group(0)
            lineno = text.count("\n", 0, m.start()) + 1
            if token.lower().startswith(("eval", "exec")) and not _takes_request_input(text, lines, m.start(), lineno):
                continue
            reasons.append(f"{path}:{lineno} 안전하지 않은 역직렬화/동적 실행: {token.strip()}")
            evidence.append(f"{path}:{lineno}: {token.strip()}")
    if reasons:
        return result(check, cfg, score=cfg.get("score_found", 0), passed=False,
                      reasons=reasons, evidence=evidence)
    return result(check, cfg, score=cfg.get("score_clean", 100), passed=True)


def _takes_request_input(text: str, lines: List[str], start: int, lineno: int) -> bool:
    """eval/exec is a finding only when THIS call takes request-derived input (its
    own argument or its line references request) — not merely because the file
    handles requests elsewhere."""
    open_idx = text.find("(", start)
    arg = _balanced_arg(text, open_idx) if open_idx != -1 else ""
    line = lines[lineno - 1] if 0 <= lineno - 1 < len(lines) else ""
    return bool(_REQUEST_NEAR.search(arg) or _REQUEST_NEAR.search(line))


# ── unrestricted_upload  (dynamic) — an upload sink that accepts and SERVES
# attacker-controlled active content (HTML/script).
# A 1x1 transparent GIF — a genuinely valid image for the positive control (an app
# with an extension/mime whitelist ACCEPTS this while rejecting the .html payload).
_GIF_1x1 = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c000000000100010000020144003b"
)


def _active_upload_is_executable(resp, marker: str, kind: str) -> bool:
    ctype = resp.headers.get("Content-Type", "").lower()
    disposition = resp.headers.get("Content-Disposition", "").lower()
    body = _body_text(resp)
    return (
        marker in body
        and kind in ctype
        and "attachment" not in disposition
    )


def dynamic_unrestricted_upload(check, ctx, cfg):
    """Upload active HTML/SVG to the avatar/upload sink, then fetch where served.
    Vulnerable only if the server returns it with an HTML content-type and the payload
    intact — judged on how the file is SERVED (a stored-but-sanitized or
    attachment/`text/plain`-served file is not a false positive). If the HTML is
    rejected, a POSITIVE CONTROL (a real image) decides defended-vs-skip: an app that
    serves the legit image but refused the HTML has a *restricted* upload (pass), while
    an app with no working upload at all is undecidable (skip — never accuse)."""
    if ctx.userA is None:
        return _undecidable(check, cfg, "업로더 세션 없음으로 판정 불가")
    sess = ctx.userA.session
    marker = uuid.uuid4().hex[:10]
    html_marker = f"UPXSS-{marker}"
    located = _upload_and_fetch(ctx, sess, f"poc-{marker}.html",
                                f"<script>{html_marker}</script>".encode(), "text/html")
    safe_evidence = []
    if located is not None:
        url, resp = located
        ctype = resp.headers.get("Content-Type", "").lower()
        if _active_upload_is_executable(resp, html_marker, "html"):
            return result(check, cfg, score=cfg.get("score_unrestricted", 0), passed=False,
                          reasons=[f"업로드한 HTML이 {url}에서 text/html로 그대로 서빙됨 → 임의 파일 업로드/저장형 XSS"],
                          evidence=[_snip(f"{url} ({ctype}): {_body_text(resp)[:120]}")])
        safe_evidence.append(_snip(
            f"업로드 HTML이 실행 컨텍스트로 서빙되지 않음 ({url}, ctype={ctype!r})"
        ))

    # SVG is commonly allow-listed as an "image" but can carry script/event
    # handlers when served inline as image/svg+xml and opened directly.
    sm = uuid.uuid4().hex[:10]
    svg_marker = f"UPSVG-{sm}"
    svg_payload = (
        f'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'{svg_marker}\')">'
        "<rect width=\"1\" height=\"1\"/></svg>"
    ).encode()
    svg = _upload_and_fetch(ctx, sess, f"poc-{sm}.svg", svg_payload, "image/svg+xml")
    if svg is not None:
        url, resp = svg
        ctype = resp.headers.get("Content-Type", "").lower()
        if _active_upload_is_executable(resp, svg_marker, "svg"):
            return result(check, cfg, score=cfg.get("score_unrestricted", 0), passed=False,
                          reasons=[f"스크립트 가능한 SVG가 {url}에서 image/svg+xml로 인라인 서빙됨 → 저장형 XSS"],
                          evidence=[_snip(f"{url} ({ctype}): {_body_text(resp)[:160]}")])
        safe_evidence.append(_snip(
            f"업로드 SVG가 실행 컨텍스트로 서빙되지 않음 ({url}, ctype={ctype!r})"
        ))

    if safe_evidence:
        return result(check, cfg, score=cfg.get("score_restricted", 100), passed=True,
                      evidence=safe_evidence)

    # Active files were rejected (or their served URLs weren't discoverable). A
    # positive control with a real image distinguishes restriction from no upload.
    # legit image must upload AND serve for us to conclude a working, restricted upload.
    m2 = uuid.uuid4().hex[:10]
    img = _upload_and_fetch(ctx, sess, f"poc-{m2}.gif", _GIF_1x1, "image/gif")
    if img is not None:
        url, _resp = img
        return result(check, cfg, score=cfg.get("score_restricted", 100), passed=True,
                      evidence=[_snip(f"정상 이미지는 {url}로 서빙되나 HTML 업로드는 거부됨 → 제한된 업로드")])
    return _undecidable(check, cfg, "업로드 기능 없음/서빙 경로 식별 불가로 판정 불가")


def _upload_and_fetch(ctx, sess, fname: str, payload: bytes, content_type: str):
    """POST the file to known upload sinks (multipart), locate the served URL (from the
    response, or by GETting the profile/post pages that render it), and GET it.
    Returns (url, response) or None."""
    for path, field in (("/profile/avatar", "image"), ("/upload", "file"),
                        ("/upload", "image"), ("/posts", "image")):
        r = ctx.upload(sess, path, field, fname, payload, content_type)
        # 200/201 (JSON) or a followed redirect to a page (also 200) both count as accepted.
        if r is None or r.status_code not in (200, 201):
            continue
        # The served file is often RENAMED, so try the response first, then the pages
        # that render it (profile, own posts) for a freshly-served image/file path.
        candidates = [_served_url(r, fname)]
        if ctx.userA is not None and ctx.userA.user_id is not None:
            candidates.append(_served_url(ctx.get(sess, f"/users/{ctx.userA.user_id}"), fname))
        candidates.append(_served_url(ctx.get(sess, "/posts"), fname))
        for url in candidates:
            if not url or not url.startswith("/"):
                continue
            got = ctx.get(sess, url)
            if got is not None and got.status_code == 200:
                return url, got
    return None


# Response keys apps use for the stored file's URL, and served-path patterns to fall
# back on (the file is usually renamed, so the original fname won't appear).
_URL_KEYS = ("avatar_url", "image_url", "url", "avatar", "image", "path",
             "location", "file", "src", "filename")
_SERVED_PATH = re.compile(
    r"""["'(]\s*(/(?:static|uploads?|avatars?|media|files?|img)/[\w./-]+"""
    r"""\.(?:png|jpe?g|gif|webp|bmp|svg|html?|txt|py))""",
    re.IGNORECASE,
)


def _served_url(resp, fname: str):
    if resp is None:
        return None
    j = _json_or_none(resp)
    if isinstance(j, dict):
        for key in _URL_KEYS:
            v = j.get(key)
            if isinstance(v, str) and v.startswith("/"):
                return v
    body = _body_text(resp)
    m = re.search(r"/[\w./-]*" + re.escape(fname), body)  # exact fname (un-renamed)
    if m:
        return m.group(0)
    m = _SERVED_PATH.search(body)  # renamed file served under an upload/static path
    return m.group(1) if m else None


CHECKS = [
    Check("insecure_deserialization", "안전하지 않은 역직렬화", "static",
          check_insecure_deserialization),
    Check("unrestricted_upload", "임의 파일 업로드", "dynamic",
          dynamic_unrestricted_upload),
]
