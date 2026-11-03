"""CSRF is judged by effect: a forged cross-site form POST (no token, attacker
Origin) must not create a post. Fake in-memory app, no Docker. Also pins the
red-team fixes in open_redirect host resolution and fast-hash detection."""
from __future__ import annotations

import pytest

from scoring.checks import A01_broken_access_control as a01
from scoring.checks import A04_cryptographic_failures as a04
from scoring.config import load_config
from scoring.shared.http import Account

_CFG = {"weight": 5, "score_protected": 100, "score_samesite_only": 50, "score_missing": 0}


class _Resp:
    def __init__(self, status=200, text="", headers=None, history=()):
        self.status_code = status
        self.text = text
        self.headers = {"Content-Type": "text/html", **(headers or {})}
        self.history = list(history)

    def json(self):
        raise ValueError


class _Board:
    """/posts accepts a post; ``origin_check`` rejects a foreign Origin, ``token``
    rejects a POST without the CSRF token, ``samesite`` decides the cookie userA got
    at its earlier login (``cookie=False``: no cookie at all)."""

    def __init__(self, *, origin_check=False, token=False, samesite=None, broken=False, cookie=True):
        self.titles, self.origin_check, self.token = [], origin_check, token
        self.samesite, self.broken = samesite, broken
        self.userA = Account(phone="01011112222", password="Prompt!Guard2345", username="alice")
        if cookie:
            rest = {"HttpOnly": None, **({"SameSite": samesite} if samesite else {})}
            self.userA.session.cookies.set("session", "x", rest=rest)
        self.logins = 0

    def post(self, sess, path, data):  # same-origin, token attached like the grader does
        if path == "/login":
            self.logins += 1
            return _Resp(200, "ok")
        if not self.broken:
            self.titles.append(data["title"])
        return _Resp(201)

    def cross_site_post(self, sess, path, data, origin="http://evil.example"):
        if self.origin_check or self.token:
            return _Resp(403, "forbidden")
        self.titles.append(data["title"])
        return _Resp(201)

    def get(self, sess, path, headers=None):
        return _Resp(200, " ".join(self.titles))


def _csrf(app):
    return a01.dynamic_csrf_protection(next(c for c in a01.CHECKS if c.id == "csrf_protection"), app, _CFG)


@pytest.mark.parametrize("app", [_Board(origin_check=True), _Board(token=True)], ids=["origin", "token"])
def test_rejected_forgery_is_protected(app):
    r = _csrf(app)
    assert r.passed is True and r.score == 100


def test_forgery_landing_with_samesite_cookie_is_partial():
    r = _csrf(_Board(samesite="Lax"))
    assert r.passed is False and r.score == 50


def test_forgery_landing_without_samesite_is_missing():
    r = _csrf(_Board())
    assert r.passed is False and r.score == 0


def test_samesite_is_read_without_logging_userA_in_again():
    # A second login would end userA's session in a one-session-per-user app.
    app = _Board(samesite="Strict")
    assert _csrf(app).score == 50 and app.logins == 0


def test_no_session_cookie_is_undecidable_not_missing():
    assert _csrf(_Board(cookie=False)).skipped is True


def test_no_working_post_is_undecidable():
    assert _csrf(_Board(broken=True)).skipped is True


class _Ctx:
    base_url = "http://127.0.0.1:5000"


@pytest.mark.parametrize("location, offsite", [
    ("https://evil.example/x", True),
    ("//evil.example/x", True),
    ("/\\evil.example/x", True),        # browsers read /\ as //
    ("/%5Cevil.example/x", False),      # an encoded backslash stays a same-site path
    ("/posts?ref=evil.example", False),
])
def test_open_redirect_resolves_location_like_a_browser(location, offsite):
    assert a01._offsite(_Ctx(), _Resp(302, headers={"Location": location})) is offsite


@pytest.mark.parametrize("line, weak", [
    ("pw_hash = hashlib.sha256(password.encode()).hexdigest()", True),
    ("pw_hash = hashlib.md5(password.encode()).hexdigest()", True),
    ("dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200000)", False),
])
def test_bare_digest_of_a_password_is_weak(line, weak):
    from scoring.engine.runner import StaticContext
    sctx = StaticContext(sources=[("app.py", line)], templates=[], requirements=[],
                         requirements_path=None, app_dir=".", config=load_config())
    check = next(c for c in a04.CHECKS if c.id == "password_hashing")
    r = a04.check_password_hashing(check, sctx, {})
    assert (r.score < 100) is weak


class _LimitedLogin(_Ctx):
    """Login answers the control with 302 /posts, then is rate limited: every later
    login gets ``limited`` (a 429, or a 200 re-rendered login form)."""

    def __init__(self, limited):
        self.limited = limited
        self.userB = Account(phone="01033334444", password="Vault!Strong2345", username="bob")
        self.live = self.userB.session

    def post(self, sess, path, data):
        return self.limited


def test_open_redirect_with_every_attack_login_refused_is_undecidable(monkeypatch):
    for limited in (_Resp(429, "too many"), _Resp(200, '<input type="password" name="password">')):
        ctx = _LimitedLogin(limited)
        answers = iter([_Resp(302, headers={"Location": "/posts"})])
        monkeypatch.setattr(a01, "_login_redirect", lambda *a: next(answers, limited))
        r = a01.dynamic_open_redirect(next(c for c in a01.CHECKS if c.id == "open_redirect"), ctx, {})
        assert r.skipped is True
        assert ctx.userB.session is ctx.live  # a refused re-login keeps userB's session


def test_open_redirect_login_refused_over_a_bad_next_is_a_defense(monkeypatch):
    # Item-0 e2e app: a login whose `next` is offsite is rejected whole (400), while the
    # same account's login with next=/posts still redirects. That is a defense, not a
    # limiter, so the check is decided.
    ok = _Resp(302, headers={"Location": "/posts"})

    def login(ctx, acct, target, where):
        return ok if target == "/posts" else _Resp(400, "이동 주소가 올바르지 않습니다.")

    ctx = _LimitedLogin(_Resp(302, headers={"Location": "/posts"}))
    monkeypatch.setattr(a01, "_login_redirect", login)
    r = a01.dynamic_open_redirect(next(c for c in a01.CHECKS if c.id == "open_redirect"), ctx, {})
    assert r.skipped is False and r.passed is True


class _NoUploadApp:
    """POST /posts ignores files; the layout shows a static logo (item: an unrelated
    /static path must not be taken for the uploaded file)."""

    def __init__(self):
        self.userA = Account(phone="01011112222", password="Prompt!Guard2345", username="alice")

    def upload(self, sess, path, field, fname, payload, ctype, extra=None):
        return _Resp(201 if path == "/posts" else 404, '<img src="/static/logo.gif">')

    def get(self, sess, path, headers=None):
        if path == "/static/logo.gif":
            r = _Resp(200, "GIF89a-logo", {"Content-Type": "image/gif"})
            r.content = b"GIF89a-logo"
            return r
        return _Resp(200, '<img src="/static/logo.gif">')


def test_upload_without_a_feature_serves_nothing_that_runs():
    # The static logo is not taken for an uploaded file, and nothing uploaded comes
    # back, so nothing can run: decided as safe, never skipped or accused.
    from scoring.checks import A08_integrity_failures as a08
    check = next(c for c in a08.CHECKS if c.id == "unrestricted_upload")
    r = a08.dynamic_unrestricted_upload(check, _NoUploadApp(), {})
    assert r.skipped is False and r.passed is True
    assert "서빙되지 않음" in r.evidence[0]
