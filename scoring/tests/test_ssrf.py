"""Unit tests for the live SSRF probe against a fake URL-consuming app.

Pins FP/FN WITHOUT Docker: an app that fetches the attacker-supplied private
callback URL scores 0; one that accepts link_url but does NOT fetch (or blocks the
private target) scores 100; an app with no URL-consuming feature, or a run without a
callback listener, SKIPS (falls back to the static ssrf_sink) — never accuses.
"""
from __future__ import annotations

from scoring.checks import A01_broken_access_control as a01

_CHECK = next(c for c in a01.CHECKS if c.id == "ssrf")
_CFG = {"wait_seconds": 0.3, "score_defended": 100, "score_vulnerable": 0}


class _Resp:
    def __init__(self, status: int, text: str = "ok"):
        self.status_code = status
        self.text = text


class _FakeCB:
    def __init__(self):
        self.port = 9999
        self._hits: set = set()

    def url_for(self, token, host):
        return f"http://{host}:{self.port}/{token}"

    def was_hit(self, token):
        return token in self._hits


class _Acct:
    def __init__(self):
        self.session = "a"


class _FakeCtx:
    def __init__(self, *, fetches, accepts=True, has_cb=True):
        self.userA = _Acct()
        self.userB = None
        self._fetches = fetches
        self._accepts = accepts
        self.ssrf_callback = _FakeCB() if has_cb else None
        self.ssrf_hosts = ["host.docker.internal", "172.17.0.1"] if has_cb else []

    def post(self, sess, path, data):
        if path in ("/posts", "/profile/avatar"):
            url = data.get("link_url") or data.get("url") or data.get("avatar_url")
            if url and self._fetches and self.ssrf_callback is not None:
                token = url.rsplit("/", 1)[-1]        # simulate a server-side fetch
                self.ssrf_callback._hits.add(token)
            return _Resp(201) if self._accepts else _Resp(400)
        return _Resp(404)

    def get(self, sess, path, headers=None):
        return _Resp(404)


def _run(ctx, cfg=None):
    return a01.dynamic_ssrf(_CHECK, ctx, cfg or _CFG)


def test_server_fetches_private_callback_scores_0():
    r = _run(_FakeCtx(fetches=True))
    assert r.passed is False and r.score == 0.0 and r.skipped is False
    assert any("SSRF" in x for x in r.penalty_reasons)


def test_accepts_but_no_fetch_scores_100():
    r = _run(_FakeCtx(fetches=False, accepts=True))
    assert r.passed is True and r.score == 100.0 and r.skipped is False


def test_no_url_feature_skips():
    # link_url/avatar_url not accepted anywhere -> can't establish the surface -> skip.
    r = _run(_FakeCtx(fetches=False, accepts=False))
    assert r.skipped is True


def test_no_callback_listener_skips():
    r = _run(_FakeCtx(fetches=True, has_cb=False))
    assert r.skipped is True


def test_missing_account_skips():
    ctx = _FakeCtx(fetches=True)
    ctx.userA = None
    r = _run(ctx)
    assert r.skipped is True
