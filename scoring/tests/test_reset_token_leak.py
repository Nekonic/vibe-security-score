"""reset_token_leak: a reset token in the reset-request response is judged by the
takeover it allows. Fake in-memory app, no Docker."""
from __future__ import annotations

import secrets

import pytest

from scoring.checks import A07_account_recovery as a07
from scoring.config import load_config
from scoring.engine import combine_scores
from scoring.models import CheckResult

_CHECK = next(c for c in a07.EARLY if c.id == "reset_token_leak")
_CFG = {"weight": 4, "score_defended": 100, "score_taken": 0, "score_leaked": 0}


class _Resp:
    def __init__(self, status=200, text="", headers=None, history=(), url="http://app/"):
        self.status_code = status
        self.text = text
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.history = list(history)
        self.url = url


class _App:
    """Spec reset flow. ``leak``: where the token goes besides stdout — "body",
    "redirect" (a Location hop) or None. ``reset_works``: whether /password/reset
    actually changes the password. ``reset``: whether the feature exists at all."""

    def __init__(self, *, leak=None, reset_works=True, reset=True, short=False):
        self.leak, self.reset_works, self.reset, self.short = leak, reset_works, reset, short
        self.users, self.tokens, self.log = {}, {}, ["Running on http://0.0.0.0:5000"]

    def app_logs(self):
        return "\n".join(self.log)

    def post(self, sess, path, data):
        if path == "/signup":
            self.users[data["username"]] = data["password"]
            return _Resp(201, '{"ok": true}')
        if path == "/login":
            ok = self.users.get(data["username"]) == data["password"]
            return _Resp(200, '{"ok": true}') if ok else _Resp(401, '{"error": "bad"}')
        if not self.reset:
            return _Resp(404, "The requested URL was not found on the server.")
        if path == "/password/reset/request":
            tok = f"{secrets.randbelow(10 ** 6):06d}" if self.short else secrets.token_urlsafe(24)
            self.tokens[tok] = data["username"]
            self.log.append(f"RESET TOKEN: {tok}")
            if self.leak == "body":
                return _Resp(200, f'{{"message": "sent", "token": "{tok}"}}')
            if self.leak == "redirect":
                hop = _Resp(302, "", headers={"Location": f"/password/reset?token={tok}"})
                return _Resp(200, "<form>new password</form>", history=[hop],
                             url=f"http://app/password/reset?token={tok}")
            return _Resp(200, '{"message": "sent"}')
        if path == "/password/reset":
            user = self.tokens.get(data["token"])
            if user is None:
                return _Resp(400, "bad")
            if self.reset_works:
                self.users[user] = data["new_password"]
            return _Resp(200, '{"ok": true}')
        raise AssertionError(path)


def _run(app):
    return a07.dynamic_reset_token_leak(_CHECK, app, _CFG)


@pytest.mark.parametrize("leak", ["body", "redirect"])
def test_leaked_token_that_takes_the_account_fails_with_critical(leak):
    r = _run(_App(leak=leak))
    assert not r.skipped and not r.passed and r.score == 0 and not r.unproven, r.penalty_reasons
    g = combine_scores(_others() + [r], load_config())
    assert [p.check_id for p in g.critical_penalties] == ["reset_token_leak"]
    assert g.critical_penalties[0].penalty == 25.0


def test_leaked_token_without_takeover_fails_without_critical():
    r = _run(_App(leak="body", reset_works=False))
    assert not r.skipped and not r.passed and r.score == 0 and r.unproven
    g = combine_scores(_others() + [r], load_config())
    assert g.critical_penalties == []


def test_token_kept_out_of_the_response_passes():
    r = _run(_App(short=True))
    assert not r.skipped and r.passed and r.score == 100


def test_no_reset_feature_is_undecidable():
    r = _run(_App(reset=False))
    assert r.skipped and not r.passed


def test_unanswered_reset_request_is_undecidable():
    app = _App()
    real = app.post
    app.post = lambda s, p, d: None if p == "/password/reset/request" else real(s, p, d)
    assert _run(app).skipped


def test_probe_does_not_touch_the_shared_accounts():
    app = _App(leak="body")
    _run(app)
    assert all(u.startswith("rst") for u in app.users)


def _others():
    return [CheckResult(check_id="rate_limiting", category="", label="", score=100.0,
                        weight=6.0, passed=True)]


def test_runs_right_after_functional():
    # Apps that leak an sqlite connection on a probe's error refuse every later write,
    # and this probe needs a signup and a password write.
    from scoring.checks import by_phase
    ids = [c.id for c in by_phase("dynamic") if c.id != "functional"]
    assert ids[0] == "reset_token_leak"
