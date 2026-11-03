"""Unit tests for the authentication probes against a fake in-memory app (no
Docker): default_credentials, rate_limiting (ISMS 5-failure rule incl. retry delay)
and weak_password_policy (a password under 8 chars)."""
from __future__ import annotations

import time
from datetime import timedelta

import pytest

from scoring.checks import A06_insecure_design as a06
from scoring.checks import A07_authentication_failures as a07
from scoring.shared.http import Account


def _check(module, cid):
    return next(c for c in module.CHECKS if c.id == cid)


class _Resp:
    def __init__(self, status=200, text="", data=None, history=()):
        self.status_code = status
        self.text = text
        self._data = data
        self.headers = {"Content-Type": "application/json" if data is not None else "text/html"}
        self.history = list(history)
        self.elapsed = timedelta(0)

    def json(self):
        if self._data is None:
            raise ValueError
        return self._data


class _Cfg(dict):
    def get(self, key, default=None):
        return dict.get(self, key, default)


class _FakeApp:
    """Minimal board: /signup, /login, /admin. ``policy(username, pw)`` decides signup;
    ``lock_after`` locks the account after N failures (423); ``delay_after`` sleeps."""

    def __init__(self, *, seed_admin=None, open_admin=False, policy=None,
                 lock_after=None, delay_after=None, delay=0.0, silent_lock=False,
                 mute_after=None, mute_admin=False, slow_landing=0.0, signup_status=None,
                 locked_db_logins=0, locked_right_logins=0):
        self.users = {}
        self.admins = set()
        if seed_admin:
            self.users[seed_admin[0]] = seed_admin[1]
            self.admins.add(seed_admin[0])
        self.open_admin = open_admin
        self.policy = policy or (lambda u, p: True)
        self.lock_after, self.delay_after, self.delay = lock_after, delay_after, delay
        self.silent_lock = silent_lock
        # No response (requests timeout → None) after N failed logins / on /admin.
        self.mute_after, self.mute_admin = mute_after, mute_admin
        # The page a successful login redirects to takes this long to render.
        self.slow_landing = slow_landing
        # /signup answers only with this (None = no response) when set.
        self.signup_status = signup_status
        # The first N logins answer 500 without counting (sqlite "database is locked").
        self.locked_db_logins = locked_db_logins
        # The first N right-password logins answer 500 (locked) before any check.
        self.locked_right_logins = locked_right_logins
        self.fails = 0
        self.authed = {}
        self.config = _Cfg({"probes.default_credentials": [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "admin123"}]})
        self.userA = Account(phone="01011112222", password="Prompt!Guard2345", username="alice")
        self.userB = Account(phone="01033334444", password="Vault!Strong2345", username="bob")
        self.users["alice"] = self.userA.password
        self.users["bob"] = self.userB.password

    def post(self, sess, path, data):
        if path == "/signup":
            if self.signup_status is not None:
                return None if self.signup_status == "none" else _Resp(self.signup_status)
            u, p = data.get("username"), data.get("password")
            if u in self.users:
                return _Resp(409)
            if not self.policy(u, p):
                return _Resp(400, data={"error": "weak password"})
            self.users[u] = p
            return _Resp(201, data={"ok": True})
        if path == "/login":
            u, p = data.get("username"), data.get("password")
            if self.mute_after is not None and self.fails >= self.mute_after:
                return None
            if self.locked_db_logins:
                self.locked_db_logins -= 1
                r = _Resp(500, "database is locked")
                r.elapsed = timedelta(0)
                return r
            waited = 0.0
            if self.delay_after is not None and self.fails >= self.delay_after:
                time.sleep(self.delay)
                waited = self.delay
            if self.lock_after is not None and self.fails >= self.lock_after:
                r = _Resp(401, data={"error": "invalid"}) if self.silent_lock else _Resp(423, "account locked")
            elif self.users.get(u) == p and self.locked_right_logins:
                self.locked_right_logins -= 1
                r = _Resp(500, "database is locked")
            elif self.users.get(u) == p:
                self.fails = 0          # like most apps: success resets the counter
                self.authed[id(sess)] = u
                # The POST answers 302 at once; the followed landing page is slow.
                r = _Resp(200, f"welcome {u} <a href=/logout>logout</a>", history=[_Resp(302)])
                r.elapsed = timedelta(seconds=self.slow_landing)
                r.history[0].elapsed = timedelta(seconds=waited)
                return r
            else:
                self.fails += 1
                r = _Resp(401, data={"error": "invalid credentials"})
            r.elapsed = timedelta(seconds=waited)
            return r
        return _Resp(404)

    def get(self, sess, path, headers=None):
        if path in ("/admin", "/admin/users"):
            if self.mute_admin:
                return None
            who = self.authed.get(id(sess))
            if self.open_admin or who in self.admins:
                return _Resp(200, "<h1>Admin</h1><table><tr><th>username</th><th>phone</th></tr></table>")
            return _Resp(403, "forbidden")
        return _Resp(404)


# ── default_credentials ────────────────────────────────────────────────────
def _defcred(app):
    return a07.dynamic_default_credentials(_check(a07, "default_credentials"), app, {})


def test_seeded_admin_with_guessable_password_is_exposed():
    r = _defcred(_FakeApp(seed_admin=("admin", "admin123")))
    assert r.passed is False and r.score == 0
    assert "admin/admin123" in r.penalty_reasons[0]


def test_no_seeded_admin_is_defended():
    r = _defcred(_FakeApp())
    assert r.passed is True and r.score == 100


def test_admin_open_to_anonymous_is_left_to_access_control():
    # Decided (no undecidable), but not deducted twice: access_control_admin owns it.
    r = _defcred(_FakeApp(seed_admin=("admin", "admin"), open_admin=True))
    assert r.skipped is False and r.passed is True and r.unproven is True


def test_no_response_from_admin_is_undecidable_not_defended():
    assert _defcred(_FakeApp(mute_admin=True)).skipped is True


# ── rate_limiting ──────────────────────────────────────────────────────────
_RL_CFG = {"attempts": 5, "delay_seconds": 0.3, "lax_attempts": 10,
           "score_present": 100, "score_lax": 50, "score_missing": 0,
           "retry_after_5xx_seconds": 0}


def _rate(app):
    return a06.dynamic_rate_limiting(_check(a06, "rate_limiting"), app, _RL_CFG)


@pytest.mark.parametrize("app", [
    _FakeApp(lock_after=3),                                   # explicit 423 block
    _FakeApp(lock_after=5, silent_lock=True),                 # correct password refused
    _FakeApp(delay_after=5, delay=0.4),                       # retry delay only
], ids=["blocked", "silent-lockout", "retry-delay"])
def test_limiting_variants_all_count(app):
    assert _rate(app).passed is True


def test_no_limit_fails():
    r = _rate(_FakeApp())
    assert r.passed is False and r.score == 0


def test_login_that_stops_answering_is_undecidable_not_limited():
    # A timeout is neither a lockout nor a retry delay.
    assert _rate(_FakeApp(mute_after=3)).skipped is True


def test_slow_page_after_login_is_not_a_retry_delay():
    r = _rate(_FakeApp(slow_landing=1.2))
    assert r.passed is False and r.score == 0


def test_failed_logins_lost_to_a_locked_db_are_measured_again():
    # #78 under load: two of five failures answered 500 and never counted, so the right
    # password still got in. Measured again on a fresh account, the 5-failure lock shows.
    r = _rate(_FakeApp(lock_after=5, silent_lock=True, locked_db_logins=2))
    assert r.passed is True and r.score == 100


def test_right_login_lost_to_a_locked_db_is_not_a_lockout():
    # No limit at all: the 500 on the right password used to read as "account locked".
    r = _rate(_FakeApp(locked_right_logins=1))
    assert r.passed is False and r.score == 0


def test_lockout_between_six_and_ten_is_partial():
    # Locks only at the 8th failure: stricter than PCI (10), looser than KISA (5).
    r = _rate(_FakeApp(lock_after=8))
    assert r.passed is False and r.score == 50


# ── weak_password_policy ───────────────────────────────────────────────────
_PW_CFG = {"short_password": "Abc12!x", "score_enforced": 100, "score_weak": 0}


def _pw(policy):
    return a07.dynamic_weak_password_policy(_check(a07, "weak_password_policy"), _FakeApp(policy=policy), _PW_CFG)


def test_length_policy_passes():
    # Digits-only or id-like passwords are not judged: 8+ chars is enough.
    r = _pw(lambda u, p: len(p) >= 8)
    assert r.passed is True and r.score == 100


def test_no_policy_scores_zero():
    r = _pw(lambda u, p: True)
    assert r.passed is False and r.score == 0


@pytest.mark.parametrize("status", ["none", 500])
def test_signup_without_an_answer_is_undecidable_not_rejected(status):
    app = _FakeApp(signup_status=status)
    r = a07.dynamic_weak_password_policy(_check(a07, "weak_password_policy"), app, _PW_CFG)
    assert r.skipped is True
