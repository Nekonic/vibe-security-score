"""Unit tests for the auth_session_management probe against a fake auth app.

Pins the two §4.5 controls deterministically WITHOUT Docker:
  - password change must verify the OLD password,
  - logout must invalidate the session,
and the FP guards: a broken/absent endpoint or an anon-open /posts must SKIP
(never accuse), positive control must pass before a verdict is credited.
"""
from __future__ import annotations

from scoring.checks import A07_authentication_failures as a07

_CHECK = next(c for c in a07.CHECKS if c.id == "auth_session_management")
_FORM = '<form><input name="password" type="password"></form>'  # login-form marker


class _Resp:
    def __init__(self, status: int, text: str = "ok"):
        self.status_code = status
        self.text = text

    def json(self):
        raise ValueError("no json")


class _FakeAuthApp:
    """Models signup/login/account-password/logout/posts with per-control knobs.
    Sessions are keyed by the identity of the requests.Session object passed in."""

    def __init__(self, *, old_pw_checked=True, logout_invalidates=True,
                 posts_require_auth=True, has_pwchange=True, has_logout=True):
        self.userA = self.userB = self.admin = None
        self.old_pw_checked = old_pw_checked
        self.logout_invalidates = logout_invalidates
        self.posts_require_auth = posts_require_auth
        self.has_pwchange = has_pwchange
        self.has_logout = has_logout
        self._users: dict = {}          # username -> {phone, password}
        self._authed: dict = {}         # session-key -> username

    def _find(self, data):
        for u, rec in self._users.items():
            if data.get("username") == u or (data.get("phone") and data.get("phone") == rec["phone"]):
                return u
        return None

    def post(self, sess, path, data):
        key = sess
        if path == "/signup":
            u = data["username"]
            self._users[u] = {"phone": data["phone"], "password": data["password"]}
            self._authed[key] = u
            return _Resp(201)
        if path == "/login":
            u = self._find(data)
            if u and self._users[u]["password"] == data.get("password"):
                self._authed[key] = u
                return _Resp(200, "welcome, logout")
            return _Resp(200, _FORM)
        if path == "/account/password":
            if not self.has_pwchange:
                return _Resp(404)
            u = self._authed.get(key)
            if not u:
                return _Resp(401)
            if self.old_pw_checked and data.get("old_password") != self._users[u]["password"]:
                return _Resp(400, "wrong old password")
            self._users[u]["password"] = data.get("new_password")
            return _Resp(200)
        if path == "/logout":
            if not self.has_logout:
                return _Resp(404)
            if self.logout_invalidates:
                self._authed.pop(key, None)
            return _Resp(200)
        if path == "/posts":
            if self.posts_require_auth and key not in self._authed:
                return _Resp(200, _FORM)
            return _Resp(201, "created")
        return _Resp(404)

    def get(self, sess, path, headers=None):
        return _Resp(404)


def _run(app):
    return a07.dynamic_auth_session_management(_CHECK, app, {})


def test_both_controls_present_scores_100():
    r = _run(_FakeAuthApp())
    assert r.passed is True and r.score == 100.0 and r.skipped is False


def test_no_old_password_check_partial():
    r = _run(_FakeAuthApp(old_pw_checked=False))
    assert r.passed is False and r.score == 40.0
    assert any("기존 비번" in x for x in r.penalty_reasons)


def test_logout_not_invalidated_partial():
    r = _run(_FakeAuthApp(logout_invalidates=False))
    assert r.passed is False and r.score == 40.0
    assert any("세션 무효화" in x for x in r.penalty_reasons)


def test_both_broken_scores_0():
    r = _run(_FakeAuthApp(old_pw_checked=False, logout_invalidates=False))
    assert r.passed is False and r.score == 0.0
    assert len(r.penalty_reasons) == 2


def test_no_password_endpoint_and_no_logout_skips():
    # neither control can be established -> undecidable, never accuse.
    r = _run(_FakeAuthApp(has_pwchange=False, has_logout=False))
    assert r.skipped is True


def test_anon_open_posts_does_not_false_flag_logout():
    # /posts accepts anonymous posts, so a post after logout is NOT proof the session
    # survived -> logout half must skip (here pw-change still passes -> overall pass).
    r = _run(_FakeAuthApp(posts_require_auth=False))
    assert r.passed is True and r.score == 100.0
