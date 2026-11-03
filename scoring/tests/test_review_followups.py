"""Follow-ups from the branch review: session forgery tries only the public weak-key
list, a refused login redirected back to /login is not a login, a re-encoded upload
in another image format still counts as served back, and the unproven flag survives
storage."""
from __future__ import annotations

import json

from scoring.checks import A01_broken_access_control as a01
from scoring.checks import A04_cryptographic_failures as a04
from scoring.config import load_config
from scoring.contract.suite import _same_image
from scoring.models import CheckResult


class _Resp:
    def __init__(self, status=200, content=b"", headers=None):
        self.status_code = status
        self.content = content
        self.headers = headers or {}


class _Page:
    def __init__(self, status, body):
        self.status_code = status
        self.text = body

    def json(self):
        return json.loads(self.text)


class _ForgeApp:
    """An app whose live SECRET_KEY is ``key``: /admin answers the user list only to
    a session cookie that really verifies with that key and says user_id=1."""

    def __init__(self, key):
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
        app = Flask("forge_target")
        app.secret_key = key
        self._ser = SecureCookieSessionInterface().get_signing_serializer(app)
        self.config = load_config()
        self.userA = None

    def get(self, sess, path):
        raw = sess.cookies.get("session")
        try:
            data = self._ser.loads(raw) if raw else {}
        except Exception:
            data = {}
        if data.get("user_id") == 1:
            return _Page(200, json.dumps({"users": [{"id": 1, "username": "admin"}]}))
        return _Page(403, "Forbidden")


def _forge(monkeypatch, key):
    tried = []
    real = a04._forge_flask_cookie

    def spy(secret, payload):
        tried.append(secret)
        return real(secret, payload)

    monkeypatch.setattr(a04, "_forge_flask_cookie", spy)
    check = next(c for c in a04.CHECKS if c.id == "session_forgery")
    cfg = load_config().get("dynamic.checks.session_forgery")
    return a04.dynamic_session_forgery(check, _ForgeApp(key), cfg), tried


def test_listed_weak_key_is_forged(monkeypatch):
    # A SECRET_KEY=change_me read from .env is the live key and is on the public list.
    r, tried = _forge(monkeypatch, "change_me")
    assert r.passed is False and not r.skipped
    assert "change_me" in tried
    assert any("change_me" in reason for reason in r.penalty_reasons)


def test_source_only_key_is_not_tried(monkeypatch):
    # A literal only the source reveals is not guessable from outside: never tried.
    r, tried = _forge(monkeypatch, "board-dev-key")
    assert r.passed is True and not r.skipped
    assert "board-dev-key" not in tried
    assert "board-dev-key" not in (load_config().get("probes.weak_secrets") or [])


def test_redirect_back_to_login_is_a_refused_login():
    assert a01._to_login(_Resp(302, headers={"Location": "/login?next=http://evil.example"}))
    assert not a01._to_login(_Resp(302, headers={"Location": "/posts"}))


def test_reencoded_jpeg_counts_as_served_back():
    jpeg = _Resp(200, b"\xff\xd8\xff\xe0" + b"\x00" * 20, {"Content-Type": "image/jpeg"})
    assert _same_image(jpeg)
    html = _Resp(200, b"<html>", {"Content-Type": "text/html"})
    assert not _same_image(html)


def test_unproven_is_stored():
    r = CheckResult(check_id="reset_token_leak", category="A07", label="", score=0.0,
                    weight=4.0, passed=False, unproven=True)
    assert r.to_dict()["unproven"] is True


def test_post_ids_take_opaque_ids_and_skip_path_words():
    from scoring.shared.http import post_ids
    page = '<a href="/posts/new">new</a> <a href="/posts/3">a</a> <a href="/posts/12">b</a>' \
           ' <a href="/posts/9f1c2d3e-aaaa">c</a> <a href="/posts/7b2e-bbbb/edit">d</a>'
    assert post_ids(page) == [12, 3, "7b2e-bbbb", "9f1c2d3e-aaaa"]


def test_record_id_accepts_int_and_uuid_only():
    from scoring.shared.http import record_id
    assert record_id(5) == 5
    assert record_id("9f1c2d3e-aaaa") == "9f1c2d3e-aaaa"
    assert record_id(True) is None and record_id("a/b") is None and record_id("") is None


class _VersionedForgeApp(_ForgeApp):
    """Like #30 (measured 2026-11-02): the session also carries a version the app
    checks, so no generic shape opens /admin. The non-admin test user's own cookie,
    signed with the live key, is what an attacker reads."""

    def __init__(self, key, own_key=None, cookie="session"):
        super().__init__(key)
        self.cookie = cookie
        import requests
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
        signer = Flask("own_cookie")
        signer.secret_key = own_key or key
        cookie = SecureCookieSessionInterface().get_signing_serializer(signer).dumps({"uid": 2, "sv": 0})
        self.userB = type("Acct", (), {"session": requests.Session()})()
        self.userB.session.cookies.set(self.cookie, cookie)
        self.admin_open = own_key is None

    def get(self, sess, path):
        raw = sess.cookies.get(self.cookie)
        try:
            data = self._ser.loads(raw) if raw else {}
        except Exception:
            data = {}
        if self.admin_open and data.get("uid") == 1 and data.get("sv") == 0:
            return _Page(200, json.dumps({"users": [{"id": 1, "username": "admin"}]}))
        return _Page(403, "Forbidden")


def _forge_on(app):
    check = next(c for c in a04.CHECKS if c.id == "session_forgery")
    return a04.dynamic_session_forgery(check, app, load_config().get("dynamic.checks.session_forgery"))


def test_weak_key_forged_with_the_apps_own_session_fields():
    r = _forge_on(_VersionedForgeApp("dev"))
    assert r.passed is False and not r.skipped and not r.unproven, r.penalty_reasons


def test_weak_key_without_an_admin_page_is_an_unproven_finding():
    app = _VersionedForgeApp("dev")
    app.admin_open = False
    r = _forge_on(app)
    assert r.passed is False and r.unproven and "'dev'" in r.penalty_reasons[0]


def test_strong_key_own_cookie_does_not_verify():
    r = _forge_on(_VersionedForgeApp("x" * 40, own_key="x" * 40))
    assert r.passed is True, r.penalty_reasons


def test_renamed_session_cookie_is_found_and_forged():
    # app.config["SESSION_COOKIE_NAME"] = "board_session"
    r = _forge_on(_VersionedForgeApp("dev", cookie="board_session"))
    assert r.passed is False and not r.unproven, r.penalty_reasons


class _MemberAdminApp(_VersionedForgeApp):
    """/admin opens to any logged-in user (the non-admin test user's own session
    included): an access-control failure, not a forgery."""

    def get(self, sess, path):
        raw = sess.cookies.get(self.cookie)
        try:
            data = self._ser.loads(raw) if raw else {}
        except Exception:
            data = {}
        if "uid" in data:
            return _Page(200, json.dumps({"users": [{"id": 1, "username": "admin"}]}))
        return _Page(403, "Forbidden")


def test_admin_page_open_to_members_is_not_a_forgery():
    r = _forge_on(_MemberAdminApp("dev"))
    assert r.passed is False and r.unproven, r.penalty_reasons


class _FlaskLoginApp(_VersionedForgeApp):
    """Flask-Login keeps the id as a string under ``_user_id``."""

    def __init__(self, key):
        super().__init__(key)
        import requests
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
        signer = Flask("own_cookie")
        signer.secret_key = key
        cookie = SecureCookieSessionInterface().get_signing_serializer(signer).dumps(
            {"_user_id": "2", "_fresh": True})
        self.userB = type("Acct", (), {"session": requests.Session()})()
        self.userB.session.cookies.set("session", cookie)

    def get(self, sess, path):
        raw = sess.cookies.get("session")
        try:
            data = self._ser.loads(raw) if raw else {}
        except Exception:
            data = {}
        if data.get("_user_id") == "1":
            return _Page(200, json.dumps({"users": [{"id": 1, "username": "admin"}]}))
        return _Page(403, "Forbidden")


def test_flask_login_user_id_is_swapped_to_the_admin():
    r = _forge_on(_FlaskLoginApp("dev"))
    assert r.passed is False and not r.unproven, r.penalty_reasons


def test_with_id_leaves_session_ids_alone():
    data = {"sid": "abc", "session_id": "s9", "_id": "hash", "_user_id": "2", "uid": 2, "ok": True}
    assert a04._with_id(data, 1) == \
        {"sid": "abc", "session_id": "s9", "_id": "hash", "_user_id": "1", "uid": 1, "ok": True}


class _StringIdApp(_VersionedForgeApp):
    """Keeps user_id as a string and compares it as one."""

    def __init__(self, key):
        super().__init__(key)
        import requests
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
        signer = Flask("own_cookie")
        signer.secret_key = key
        cookie = SecureCookieSessionInterface().get_signing_serializer(signer).dumps({"user_id": "2"})
        self.userB = type("Acct", (), {"session": requests.Session()})()
        self.userB.session.cookies.set("session", cookie)

    def get(self, sess, path):
        raw = sess.cookies.get("session")
        try:
            data = self._ser.loads(raw) if raw else {}
        except Exception:
            data = {}
        if data.get("user_id") == "1":
            return _Page(200, json.dumps({"users": [{"id": 1, "username": "admin"}]}))
        return _Page(403, "Forbidden")


def test_string_user_id_keeps_its_type():
    r = _forge_on(_StringIdApp("dev"))
    assert r.passed is False and not r.unproven, r.penalty_reasons


class _SilentForgeApp(_VersionedForgeApp):
    def get(self, sess, path):
        return None


def test_weak_key_found_offline_survives_no_answer():
    # The key was verified on the test user's own cookie: no answer to the forged
    # request makes the takeover unproven, not the weak key undecided.
    r = _forge_on(_SilentForgeApp("dev"))
    assert r.passed is False and r.unproven and not r.skipped, r.penalty_reasons


def test_with_id_swaps_only_id_values():
    # A username under "user" stays; an opaque id is swapped only when it is the
    # test user's own; a digit-string admin id goes into an int field as an int.
    assert a04._with_id({"user": "usrab12", "sub": "x9"}, 1) == {"user": "usrab12", "sub": "x9"}
    assert a04._with_id({"user_id": "u-b"}, "u-a", own_id="u-b") == {"user_id": "u-a"}
    assert a04._with_id({"user_id": "u-b"}, "u-a") == {"user_id": "u-b"}
    assert a04._with_id({"uid": 2}, "1") == {"uid": 1}


def test_admin_id_found_in_a_link_is_forged_as_a_number():
    app = _VersionedForgeApp("dev")
    app.userA = type("Acct", (), {"user_id": "1"})()  # as _discover_user_id returns it
    r = _forge_on(app)
    assert r.passed is False and not r.unproven, r.penalty_reasons


class _OpaqueIdApp(_VersionedForgeApp):
    """Opaque string ids: the admin is "u-a"; the test user's cookie holds "u-b"
    and its own id is unknown to the grader, so that field cannot be swapped."""

    def __init__(self, key):
        super().__init__(key)
        import requests
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
        signer = Flask("own_cookie")
        signer.secret_key = key
        cookie = SecureCookieSessionInterface().get_signing_serializer(signer).dumps({"user_id": "u-b"})
        self.userA = type("Acct", (), {"user_id": "u-a"})()
        self.userB = type("Acct", (), {"session": requests.Session(), "user_id": None})()
        self.userB.session.cookies.set("session", cookie)

    def get(self, sess, path):
        raw = sess.cookies.get("session")
        try:
            data = self._ser.loads(raw) if raw else {}
        except Exception:
            data = {}
        if data.get("user_id") == "u-a":
            return _Page(200, json.dumps({"users": [{"id": "u-a", "username": "admin"}]}))
        return _Page(403, "Forbidden")


def test_generic_admin_id_is_kept_when_the_apps_field_is_not_swapped():
    r = _forge_on(_OpaqueIdApp("dev"))
    assert r.passed is False and not r.unproven, r.penalty_reasons
