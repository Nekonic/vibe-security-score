"""otp_bypass, stale_session_reuse and the session-cookie leak of reset_token_leak,
against a small in-process Flask app whose real signed session cookies the probes
decode. No Docker."""
from __future__ import annotations

import secrets
from http.cookies import SimpleCookie
from types import SimpleNamespace

import pytest
import requests
from flask import Flask, abort, jsonify, request, session

from scoring.checks import A07_account_recovery as a07
from scoring.config import load_config
from scoring.engine import combine_scores
from scoring.models import CheckResult
from scoring.shared.http import Account, cookie_texts, decode_flask_session

_CFG = load_config()
_BY_ID = {c.id: c for c in a07.EARLY + a07.CHECKS}


def _cfg(cid):
    return _CFG.get(f"dynamic.checks.{cid}") or {}


def _board(otp="safe", ids="reuse", reset_cookie=False, reset_500=0, blocked_gets=0):
    """The spec's account routes. ``otp``: safe (code kept server-side), null (code
    in the session, compared as is, so a missing code equals no code), cookie (code
    in the session, compared only when given), any (no comparison). ``ids``: reuse
    (next id = max + 1, session holds only the id), autoinc (ids never reused), bound
    (session also holds the username and must still match). ``reset_500``: the first
    reset requests for an existing name answer 500 (sqlite locked under load).
    ``blocked_gets``: after 20 wrong codes an IP limiter answers GET /posts 429 this
    many times."""
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(16)
    users, codes, tokens, log, seq = {}, {}, {}, [], [0]
    left = {"reset_500": reset_500, "blocked": 0, "wrong": 0}

    def body():
        return request.get_json(silent=True) or {}

    def me():
        u = users.get(session.get("uid"))
        if u and ids == "bound" and session.get("uname") != u["username"]:
            return None
        return u

    def login_as(u):
        session.clear()
        session["uid"] = u["id"]
        session["uname"] = u["username"]

    @app.post("/signup")
    def signup():
        d = body()
        seq[0] += 1
        uid = seq[0] if ids != "reuse" else max(users, default=0) + 1
        users[uid] = u = dict(id=uid, username=d["username"], phone=d["phone"],
                              password=d["password"], admin=not users, verified=False)
        login_as(u)
        return jsonify(id=uid), 201

    @app.post("/login")
    def login():
        d = body()
        u = next((u for u in users.values() if u["username"] == d.get("username")
                  and u["password"] == d.get("password")), None)
        if not u:
            return jsonify(error="bad"), 401
        login_as(u)
        return jsonify(id=u["id"], username=u["username"])

    @app.get("/users/<int:i>")
    def profile(i):
        u = users.get(i) or abort(404)
        m = me()
        own = f" {u['phone']}" + (" 인증됨" if u["verified"] else "") if m and m["id"] == i else ""
        return f"<h1>{u['username']}</h1>{own}"

    @app.get("/admin")
    def admin():
        m = me()
        return "<h1>Admin</h1>" if m and m["admin"] else ("forbidden", 403)

    @app.get("/admin/users")
    def admin_users():
        m = me()
        if not (m and m["admin"]):
            return "forbidden", 403
        return "<h1>Admin</h1>" + " ".join(u["username"] for u in users.values())

    @app.delete("/admin/users/<int:i>")
    def admin_delete(i):
        m = me()
        if not (m and m["admin"]):
            return "forbidden", 403
        users.pop(i, None)
        return jsonify(ok=True)

    @app.post("/verify/request")
    def verify_request():
        code = f"{secrets.randbelow(10 ** 6):06d}"
        log.append(f"VERIFY CODE: {code}")
        if otp in ("safe", "soft200", "soft200_limited", "wrong_verifies"):
            codes[me()["id"]] = code
        else:
            session["verify_code"] = code
        return jsonify(ok=True)

    @app.post("/verify/confirm")
    def verify_confirm():
        c, m = body().get("code"), me()
        if otp in ("soft200", "soft200_limited", "wrong_verifies"):
            # Wrong codes answered 200 (the status says nothing): no limit, a 5-try
            # limit, or the #56 bug where a wrong code falls through to verifying.
            m["tries"] = m.get("tries", 0) + 1
            right = c is not None and c == codes.get(m["id"])
            if otp == "soft200_limited" and m["tries"] > 5:
                codes.pop(m["id"], None)
                right = False
            if right or otp == "wrong_verifies":
                m["verified"] = True
            return jsonify(ok=True)
        left["wrong"] += 1
        if left["wrong"] == 20:
            left["blocked"] = blocked_gets
        ok = {"safe": c is not None and c == codes.get(m["id"]),
              "null": c == session.get("verify_code"),
              "cookie": c is not None and c == session.get("verify_code"),
              "any": True}[otp]
        if not ok:
            return jsonify(error="wrong"), 400
        m["verified"] = True
        return jsonify(ok=True)

    @app.post("/password/reset/request")
    def reset_request():
        u = next((u for u in users.values() if u["username"] == body().get("username")), None)
        if u and left["reset_500"]:
            left["reset_500"] -= 1
            return "database is locked", 500
        if u:
            tok = secrets.token_urlsafe(24)
            tokens[tok] = u["id"]
            log.append(f"RESET TOKEN: {tok}")
            if reset_cookie:
                session["reset_" + tok] = u["id"]
        return jsonify(message="sent")

    @app.post("/password/reset")
    def reset():
        d = body()
        uid = tokens.pop(d.get("token"), None)
        if uid is None:
            return jsonify(error="bad"), 400
        users[uid]["password"] = d["new_password"]
        return jsonify(ok=True)

    @app.get("/posts")
    def posts():
        if left["blocked"]:
            left["blocked"] -= 1
            return "too many requests", 429
        return "<h1>Posts</h1>"

    return app, log


class _Ctx:
    """The DynamicContext surface the probes use, over Flask's test client: one
    client per requests.Session, and every Set-Cookie copied into that session's
    jar and the response's own, as requests would."""

    def __init__(self, app, log):
        self.app, self._log, self._clients = app, log, {}
        self.config = _CFG
        self.app_logs = lambda: "\n".join(self._log)
        self.userA = Account(phone="01011112222", password="Adm!n12345678", username="admin1")
        self.userB = None
        self.post(self.userA.session, "/signup", {"username": "admin1", "phone": "01011112222",
                                                  "password": "Adm!n12345678"})

    def _send(self, method, sess, path, data=None, **_):
        client = self._clients.setdefault(id(sess), (sess, self.app.test_client()))[1]
        r = client.open(path, method=method, json=data)
        jar = requests.cookies.RequestsCookieJar()
        for h in r.headers.getlist("Set-Cookie"):
            for name, morsel in SimpleCookie(h).items():
                jar.set(name, morsel.value)
                sess.cookies.set(name, morsel.value)
        return SimpleNamespace(status_code=r.status_code, text=r.get_data(as_text=True),
                               headers=dict(r.headers), history=[], url="http://app" + path,
                               cookies=jar, json=r.get_json)

    def get(self, sess, path, **kw):
        return self._send("GET", sess, path, **kw)

    def post(self, sess, path, data):
        return self._send("POST", sess, path, data)

    def delete(self, sess, path, data=None):
        return self._send("DELETE", sess, path, data)


def _run(cid, cfg=None, **board):
    app, log = _board(**board)
    ctx = _Ctx(app, log)
    c = _BY_ID[cid]
    return c.fn(c, ctx, {**_cfg(cid), **(cfg or {})})


# ── cookie decoding ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("payload", [{"verify_code": "123456"},
                                     {"reset_" + "x" * 40: 1, "pad": "a" * 400}])
def test_decode_flask_session_reads_plain_and_compressed_cookies(payload):
    from flask.sessions import SecureCookieSessionInterface
    app = Flask(__name__)
    app.secret_key = "k"
    value = SecureCookieSessionInterface().get_signing_serializer(app).dumps(payload)
    assert value.startswith(".") == ("pad" in payload)   # long payloads get zlib'd
    text = decode_flask_session(value)
    assert all(k in text for k in payload)


@pytest.mark.parametrize("value", ["", "abc", "not.a.cookie", ".!!!.x.y"])
def test_decode_flask_session_ignores_other_values(value):
    assert decode_flask_session(value) == ""


def test_cookie_texts_reads_response_hops_and_sessions():
    from flask.sessions import SecureCookieSessionInterface
    app = Flask(__name__)
    app.secret_key = "k"
    v = SecureCookieSessionInterface().get_signing_serializer(app).dumps({"verify_code": "654321"})
    hop = SimpleNamespace(cookies={"session": v}, history=[])
    final = SimpleNamespace(cookies={}, history=[hop])
    sess = requests.Session()
    sess.cookies.set("session", v)
    assert any("654321" in t for t in cookie_texts(final))
    assert any("654321" in t for t in cookie_texts(sess))


# ── otp_bypass ──────────────────────────────────────────────────────────────
def test_otp_bypass_passes_when_the_code_stays_server_side():
    r = _run("otp_bypass", otp="safe")
    assert not r.skipped and r.passed and r.score == 100, r.penalty_reasons


def test_otp_bypass_fails_when_a_missing_code_matches_no_code():
    r = _run("otp_bypass", otp="null")
    assert not r.skipped and not r.passed and r.score == 0
    assert "null" in r.penalty_reasons[0]


def test_otp_bypass_fails_when_the_code_is_read_from_the_cookie():
    r = _run("otp_bypass", otp="cookie")
    assert not r.skipped and not r.passed and r.score == 0
    assert "쿠키" in r.penalty_reasons[0]


def test_otp_bypass_fails_when_any_code_verifies():
    r = _run("otp_bypass", otp="any")
    assert not r.skipped and not r.passed and r.score == 0


def test_otp_bypass_is_never_a_critical():
    r = _run("otp_bypass", otp="null")
    g = combine_scores([r, _ok("rate_limiting")], _CFG)
    assert g.critical_penalties == [] and g.raw_score < 100


# ── stale_session_reuse ─────────────────────────────────────────────────────
def test_stale_session_reuse_fails_when_the_old_cookie_becomes_the_next_user():
    r = _run("stale_session_reuse", ids="reuse")
    assert not r.skipped and not r.passed and r.score == 0, r.penalty_reasons


@pytest.mark.parametrize("ids", ["autoinc", "bound"])
def test_stale_session_reuse_passes_when_ids_or_sessions_are_not_reused(ids):
    r = _run("stale_session_reuse", ids=ids)
    assert not r.skipped and r.passed and r.score == 100, r.penalty_reasons


def test_stale_session_reuse_is_never_a_critical():
    r = _run("stale_session_reuse", ids="reuse")
    g = combine_scores([r, _ok("rate_limiting")], _CFG)
    assert g.critical_penalties == [] and g.raw_score < 100


# ── reset_token_leak: the token in the requester's session cookie ───────────
def test_reset_token_in_the_session_cookie_is_the_takeover_critical():
    r = _run("reset_token_leak", reset_cookie=True)
    assert not r.skipped and not r.passed and not r.unproven, r.penalty_reasons
    assert any("세션 쿠키" in e for e in r.evidence)
    g = combine_scores([r, _ok("rate_limiting")], _CFG)
    assert [(p.check_id, p.penalty) for p in g.critical_penalties] == [("reset_token_leak", 25.0)]


def test_reset_token_kept_out_of_the_cookie_passes():
    r = _run("reset_token_leak")
    assert not r.skipped and r.passed


@pytest.mark.parametrize("otp, passed", [("soft200", False), ("soft200_limited", True),
                                         ("wrong_verifies", False), ("safe", False)])
def test_otp_bruteforce_judges_by_the_profile_when_wrong_codes_get_200(otp, passed):
    # "safe" keeps the code with no attempt limit, so 20 misses then the right code
    # still verify: a brute-force finding, judged by status as before.
    r = _run("otp_bruteforce", otp=otp)
    assert r.skipped is False and r.passed is passed, r.penalty_reasons


def test_account_probes_run_right_after_functional():
    from scoring.checks import by_phase
    ids = [c.id for c in by_phase("dynamic") if c.id != "functional"]
    assert ids[:3] == ["reset_token_leak", "otp_bypass", "stale_session_reuse"]


def _ok(cid):
    return CheckResult(check_id=cid, category="", label="", score=100.0, weight=6.0, passed=True)


def test_reset_enumeration_asks_again_after_a_5xx_under_load():
    # Only the existing name writes a reset row, so only it hit the locked database.
    r = _run("reset_enumeration", cfg={"retry_after_5xx_seconds": 0}, reset_500=1)
    assert not r.skipped and r.passed, r.penalty_reasons


def test_reset_enumeration_judges_a_5xx_that_stays():
    r = _run("reset_enumeration", cfg={"retry_after_5xx_seconds": 0}, reset_500=2)
    assert not r.skipped and not r.passed


def test_otp_bruteforce_waits_out_a_tripped_limiter(monkeypatch):
    monkeypatch.setattr(a07.time, "sleep", lambda s: None)
    app, log = _board(otp="safe", blocked_gets=3)
    ctx = _Ctx(app, log)
    c = _BY_ID["otp_bruteforce"]
    c.fn(c, ctx, _cfg("otp_bruteforce"))
    assert ctx.get(requests.Session(), "/posts").status_code == 200


def test_new_log_entry_is_found_when_the_tail_scrolls():
    # app_logs is a tail: one old link scrolled out as the new one came in.
    assert a07._new_entry(["t1", "t2", "t3"], ["t2", "t3", "t4"]) == "t4"
    assert a07._new_entry(["t1", "t2"], ["t1", "t2"]) is None
    assert a07._new_entry([], ["t1"]) == "t1"
