"""Unit tests for the IDOR probe (idor_profile) against a fake profile app.

Pins the verdict logic deterministically WITHOUT Docker. The key regression this
guards: an app that correctly access-controls /users/<id> (403 to non-owners) but
keeps the phone (private PII) OUT of its rendered HTML profile must NOT be scored
"control broken" (60) — the probe now reads the phone from the HTML *and* JSON
surface, and credits a demonstrated attacker denial as defended.
"""
from __future__ import annotations

import re

from scoring.checks import A01_broken_access_control as a01

_CHECK = next(c for c in a01.CHECKS if c.id == "idor_profile")
_USERS_RE = re.compile(r"^/users/(\d+)$")
_PHONE = "01011112222"  # userA's phone; digits the probe hunts for


class _Resp:
    def __init__(self, status: int, text: str = ""):
        self.status_code = status
        self.text = text


class _Acct:
    def __init__(self, sid: str, phone: str, uid):
        self.session = sid
        self.phone = phone
        self.user_id = uid


class _Ctx:
    """Serves /users/1 (userA's profile). Owner (session 'a') and attacker
    (session 'b') outcomes are configured per-surface (HTML vs JSON)."""

    def __init__(self, *, owner_html_phone=True, owner_json_phone=False,
                 atk_html_phone=False, atk_json_phone=False, atk_code=403):
        self.userA = _Acct("a", _PHONE, 1)
        self.userB = _Acct("b", "01033334444", 2)
        self.admin = None
        self._c = dict(owner_html_phone=owner_html_phone, owner_json_phone=owner_json_phone,
                       atk_html_phone=atk_html_phone, atk_json_phone=atk_json_phone,
                       atk_code=atk_code)

    def get(self, sess, path, headers=None):
        m = _USERS_RE.match(path)
        if not m:
            return _Resp(404)
        want_json = bool(headers and "json" in str(headers.get("Accept", "")).lower())
        c = self._c
        if sess == "a" and int(m.group(1)) == 1:
            show = c["owner_json_phone"] if want_json else c["owner_html_phone"]
            return _Resp(200, _PHONE if show else "profile: name, avatar, posts")
        if sess == "a":  # owner reading someone else -> access-controlled too
            return _Resp(403, "forbidden")
        if sess == "b":
            leak = c["atk_json_phone"] if want_json else c["atk_html_phone"]
            if leak:
                return _Resp(200, _PHONE)
            return _Resp(c["atk_code"], "blocked")
        return _Resp(404)


def _run(ctx):
    return a01.dynamic_idor_profile(_CHECK, ctx, {})


def test_defended_html_scores_100():
    r = _run(_Ctx(owner_html_phone=True, atk_code=403))
    assert r.passed is True and r.score == 100.0 and r.skipped is False


def test_leak_scores_0():
    r = _run(_Ctx(owner_html_phone=True, atk_html_phone=True))
    assert r.passed is False and r.score == 0.0
    assert any("IDOR" in x for x in r.penalty_reasons)


def test_json_only_leak_is_caught():
    # phone never in HTML, but attacker reads it via the JSON surface -> still IDOR.
    r = _run(_Ctx(owner_html_phone=False, owner_json_phone=True,
                  atk_html_phone=False, atk_json_phone=True))
    assert r.passed is False and r.score == 0.0


def test_phone_hidden_from_html_but_attacker_blocked_scores_100():
    # THE REGRESSION: owner's phone isn't in the rendered profile and isn't in JSON
    # either, but non-owners get 403. Previously "control broken" (60); now defended.
    r = _run(_Ctx(owner_html_phone=False, owner_json_phone=False, atk_code=403))
    assert r.passed is True and r.score == 100.0
    assert any("차단" in x for x in r.penalty_reasons)


def test_phone_readable_only_via_json_control_establishes_defended():
    # Owner's phone shows only in JSON; attacker blocked -> control established, defended.
    r = _run(_Ctx(owner_html_phone=False, owner_json_phone=True, atk_code=403))
    assert r.passed is True and r.score == 100.0
    assert not any("차단" in x for x in r.penalty_reasons)  # real control, no fallback note


def test_murky_no_control_no_denial_stays_control_broken():
    # Owner can't show phone anywhere AND attacker got 200 (no explicit denial, no
    # phone) -> genuinely ambiguous, keep the partial "control broken" verdict.
    r = _run(_Ctx(owner_html_phone=False, owner_json_phone=False,
                  atk_html_phone=False, atk_json_phone=False, atk_code=200))
    assert r.passed is False and r.score == 60.0
    assert any("control broken" in x for x in r.penalty_reasons)


def test_missing_account_undecidable():
    ctx = _Ctx()
    ctx.userB = None
    r = _run(ctx)
    assert r.skipped is True
