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
def dynamic_unrestricted_upload(check, ctx, cfg):
    """Upload an HTML file to the avatar/upload sink, then fetch where it is served.
    Vulnerable only if the server returns it with an HTML content-type and the
    payload intact — judged on how the file is SERVED, so a stored-but-sanitized or
    attachment/`text/plain`-served file is not a false positive. No upload sink or a
    non-served upload → skip (never accuse)."""
    if ctx.userA is None:
        return _undecidable(check, cfg, "업로더 세션 없음으로 판정 불가")
    marker = uuid.uuid4().hex[:10]
    fname = f"poc-{marker}.html"
    payload = f"<script>UPXSS-{marker}</script>".encode()
    located = _upload_and_fetch(ctx, ctx.userA.session, fname, payload)
    if located is None:
        return _undecidable(check, cfg, "업로드 기능 없음/서빙 경로 식별 불가로 판정 불가")
    url, resp = located
    ctype = resp.headers.get("Content-Type", "").lower()
    if f"UPXSS-{marker}" in _body_text(resp) and "html" in ctype:
        return result(check, cfg, score=cfg.get("score_unrestricted", 0), passed=False,
                      reasons=[f"업로드한 HTML이 {url}에서 text/html로 그대로 서빙됨 → 임의 파일 업로드/저장형 XSS"],
                      evidence=[_snip(f"{url} ({ctype}): {_body_text(resp)[:120]}")])
    return result(check, cfg, score=cfg.get("score_restricted", 100), passed=True,
                  evidence=[_snip(f"업로드 파일이 실행 컨텍스트로 서빙되지 않음 ({url}, ctype={ctype!r})")])


def _upload_and_fetch(ctx, sess, fname: str, payload: bytes):
    """POST the file to known upload sinks (multipart), locate the served URL from
    the response JSON/body, and GET it. Returns (url, response) or None."""
    for path, field in (("/profile/avatar", "image"), ("/upload", "file"), ("/posts", "image")):
        try:
            r = sess.post(ctx._url(path), files={field: (fname, payload, "text/html")},
                          timeout=ctx.http_timeout)
        except requests.RequestException:
            continue
        if r is None or r.status_code not in (200, 201):
            continue
        url = _served_url(r, fname)
        if not url or not url.startswith("/"):
            continue
        got = ctx.get(sess, url)
        if got is not None and got.status_code == 200:
            return url, got
    return None


def _served_url(resp, fname: str):
    j = _json_or_none(resp)
    if isinstance(j, dict):
        for key in ("avatar_url", "url", "path", "location", "file"):
            v = j.get(key)
            if isinstance(v, str) and v:
                return v
    m = re.search(r"/[\w./-]*" + re.escape(fname), _body_text(resp))
    return m.group(0) if m else None


CHECKS = [
    Check("insecure_deserialization", "안전하지 않은 역직렬화", "static",
          check_insecure_deserialization),
    Check("unrestricted_upload", "임의 파일 업로드", "dynamic",
          dynamic_unrestricted_upload),
]
