"""Live app preview: a logged-in user opens a graded submission's generated app at
/submissions/<id>/app/... The grader reverse-proxies each request to that
submission's preview container (``preview_session``).

Generated apps are written for the site root (``href="/posts"``, ``Path=/`` cookies,
``Location: /login``), so responses are rewritten onto the ``/submissions/<id>/app``
prefix: root-relative URLs in HTML/CSS, redirect targets and cookie paths. The
grader's own session/CSRF cookies are never forwarded to the app.

While the submission is GENERATING, the target is Codex's own self-test server
(its per-run port, recorded by ``codex_runner``), so the result page can show the
app taking shape live; from SCORING on it is the preview container.
"""
from __future__ import annotations

import re
from http.cookies import CookieError, Morsel
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

import requests
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.clickjacking import xframe_options_sameorigin
from django.views.decorators.csrf import csrf_exempt

from . import preview_session
from .models import Submission

_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
}
_SKIP_REQUEST = _HOP_BY_HOP | {
    "host", "content-length", "cookie", "accept-encoding", "origin", "referer",
}
_SKIP_RESPONSE = _HOP_BY_HOP | {
    "content-length", "content-encoding", "content-type", "set-cookie", "location",
    "date", "server",
    "x-frame-options",  # the result page embeds the app; framing is set below
}

# Root-relative URL in an HTML attribute / CSS url(): `/x` but not `//host/x`.
# data-url / data-next carry the PATCH/DELETE targets static/board.js fetches.
_ATTR_URL = re.compile(rb"""(\b(?:href|src|action|formaction|poster|data-url|data-next)\s*=\s*["']?)/(?!/)""", re.I)
_CSS_URL = re.compile(rb"""(url\(\s*["']?)/(?!/)""", re.I)


def prefix_for(pk: int) -> str:
    return f"/submissions/{pk}/app"


def rewrite_body(content: bytes, content_type: str, prefix: str) -> bytes:
    p = prefix.encode()
    ctype = (content_type or "").lower()
    if "text/html" in ctype:
        content = _ATTR_URL.sub(lambda m: m.group(1) + p + b"/", content)
        return _CSS_URL.sub(lambda m: m.group(1) + p + b"/", content)
    if "text/css" in ctype:
        return _CSS_URL.sub(lambda m: m.group(1) + p + b"/", content)
    return content


def without_frame_ancestors(csp: str) -> str:
    """The app's CSP minus ``frame-ancestors``, so the result page can embed it."""
    keep = [d.strip() for d in csp.split(";")
            if d.strip() and not d.strip().lower().startswith("frame-ancestors")]
    return "; ".join(keep)


def rewrite_location(location: str, prefix: str) -> str:
    """Map the app's redirect target onto the preview prefix. Absolute URLs pointing
    at the app itself (127.0.0.1/localhost) become root-relative first; other hosts
    and relative paths are left alone."""
    parts = urlsplit(location)
    if parts.netloc:
        if parts.hostname not in ("127.0.0.1", "localhost"):
            return location
        location = urlunsplit(("", "", parts.path or "/", parts.query, parts.fragment))
    if location.startswith("/") and not location.startswith("//"):
        return prefix + location
    return location


def proxied_cookie(raw: str, prefix: str, secure_request: bool) -> Optional[Morsel]:
    """The app's Set-Cookie re-scoped to the preview prefix (value kept verbatim).
    Over plain HTTP a Secure cookie would be dropped by the browser and the app's
    login would silently fail, so Secure (and SameSite=None, which needs it) is
    removed there."""
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    morsel = Morsel()
    try:
        morsel.set(name.strip(), value, value)
    except CookieError:
        return None
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key = key.strip().lower()
        if key in ("expires", "max-age", "samesite"):
            morsel[key] = val.strip()
        elif key in ("httponly", "secure"):
            morsel[key] = True
    if not secure_request:
        morsel["secure"] = ""
        if morsel["samesite"].lower() == "none":
            morsel["samesite"] = ""
    morsel["path"] = prefix + "/"
    return morsel


def _forward_cookies(raw: str) -> str:
    """The browser's Cookie header minus the grader's own session/CSRF cookies."""
    own = {settings.SESSION_COOKIE_NAME, settings.CSRF_COOKIE_NAME}
    keep = []
    for pair in raw.split(";"):
        name = pair.split("=", 1)[0].strip()
        if name and name not in own:
            keep.append(pair.strip())
    return "; ".join(keep)


def _status_page(request, sub, *, title, message, logs=""):
    return render(
        request,
        "submissions/preview_status.html",
        {"sub": sub, "title": title, "message": message, "logs": logs},
        status=503,
    )


def _not_running(request, sub, title, message):
    """The preview app died or never answered: show its log and drop the container
    so the next visit boots it fresh."""
    logs = preview_session.logs(sub.pk)
    preview_session.remove(sub.pk)
    return _status_page(request, sub, title=title, message=message, logs=logs)


def _body(request) -> bytes:
    """The request body, read once: a fast-path forward that finds the app down
    is retried after the docker re-check, with the same body."""
    if not hasattr(request, "_preview_body"):
        request._preview_body = request.read()
    return request._preview_body


class _AppDown(Exception):
    """The app at the target port isn't answering (booting, restarting, or gone)."""


def _forward(request, pk: int, port: int, cfg) -> HttpResponse:
    """Send this request to the app on ``port`` and rewrite the answer onto the
    preview prefix. Raises ``_AppDown`` when nothing is listening."""
    prefix = prefix_for(pk)
    base = f"http://127.0.0.1:{port}"
    # Forward the still-escaped path + query exactly as the browser sent it.
    url = base + (request.get_full_path()[len(prefix):] or "/")

    headers = {k: v for k, v in request.headers.items() if k.lower() not in _SKIP_REQUEST}
    cookies = _forward_cookies(request.META.get("HTTP_COOKIE", ""))
    if cookies:
        headers["Cookie"] = cookies
    # Apps that check Origin/Referer should see their own origin, as when used directly.
    if "Origin" in request.headers:
        headers["Origin"] = base
    referer = request.headers.get("Referer", "")
    if prefix in referer:
        headers["Referer"] = base + referer.split(prefix, 1)[1]

    try:
        resp = requests.request(
            request.method, url, headers=headers, data=_body(request),
            allow_redirects=False,
            timeout=float(cfg.get("preview.request_timeout_seconds", 15)),
        )
    except requests.ConnectionError as exc:
        raise _AppDown() from exc

    content_type = resp.headers.get("Content-Type", "")
    out = HttpResponse(rewrite_body(resp.content, content_type, prefix),
                       status=resp.status_code,
                       content_type=content_type or "application/octet-stream")
    for key, value in resp.headers.items():
        if key.lower() not in _SKIP_RESPONSE:
            if key.lower() == "content-security-policy":
                value = without_frame_ancestors(value)
                if not value:
                    continue
            try:
                out[key] = value
            except Exception:  # header value Django won't emit (e.g. non-latin-1)
                continue
    if "Location" in resp.headers:
        out["Location"] = rewrite_location(resp.headers["Location"], prefix)
    for raw in resp.raw.headers.getlist("Set-Cookie"):
        morsel = proxied_cookie(raw, prefix, request.is_secure())
        if morsel is not None:
            out.cookies[morsel.key] = morsel
    return out


def _timed_out(request, sub):
    return _status_page(request, sub, title="응답 시간 초과",
                        message="새로고침")


def _proxy_or(request, sub, port, cfg, when_down):
    try:
        return _forward(request, sub.pk, port, cfg)
    except _AppDown:
        return when_down()
    except requests.Timeout:
        return _timed_out(request, sub)


def _live_generation(request, sub, cfg):
    """While Codex is still building the app, show its own self-test server."""
    from codex_runner.activity import read_preview_port

    def waiting():
        return _status_page(request, sub, title="서버 띄우는 중...",
                            message="")

    port = read_preview_port(cfg, str(sub.pk))
    if port is None:
        return waiting()
    return _proxy_or(request, sub, port, cfg, waiting)


@csrf_exempt
@xframe_options_sameorigin
@login_required
def app_proxy(request, pk: int, subpath: str = ""):
    sub = get_object_or_404(Submission, pk=pk)
    cfg = preview_session._cfg()
    S = Submission.Status
    if sub.status in (S.QUEUED, S.RATE_LIMITED):
        return _status_page(request, sub, title="대기 중",
                            message="")
    if sub.status == S.GENERATING:
        return _live_generation(request, sub, cfg)
    if sub.status == S.FAILED or not sub.workdir:
        return _status_page(request, sub, title="열 수 없는 제출",
                            message="생성 코드 없음")

    # SCORING / DONE: the harvested app in its own preview container. The first
    # request waits for it to boot (no loading page / auto-refresh).
    preview_session.reap_idle()
    # Fast path: a port docker confirmed in the last few seconds (a page and its
    # assets) is used as is. Only when the app doesn't answer there do we go back
    # to docker (state, start, readiness) below.
    port = preview_session.cached_port(pk)
    if port is not None:
        preview_session.touch(pk, cfg)
        try:
            return _forward(request, pk, port, cfg)
        except _AppDown:
            preview_session.forget_port(pk)
        except requests.Timeout:
            return _timed_out(request, sub)
    if preview_session.container_state(pk, cfg) == "missing":
        started = preview_session.start(sub)
        if not started["ok"]:
            return _status_page(request, sub, title="앱 실행 실패", message=started["error"])
    ready = preview_session.wait_ready(pk, cfg)
    if ready == "timeout":
        return _not_running(request, sub, "앱 응답 없음",
                            "부팅 시간 초과 · 새로고침")
    if not isinstance(ready, int):
        return _not_running(request, sub, "앱 실행 실패",
                            "부팅 중 종료 · 새로고침")
    preview_session.touch(pk, cfg)

    def down():
        preview_session.forget_port(pk)
        return _status_page(request, sub, title="앱 응답 없음",
                            message="새로고침")

    return _proxy_or(request, sub, ready, cfg, down)
