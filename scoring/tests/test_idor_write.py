"""idor_write against a small in-process Flask board: another user must not edit or
delete someone's post or comment. Judged by what the post page shows, never by the
status code. No Docker."""
from __future__ import annotations

import secrets

import pytest
from flask import Flask, abort, jsonify, request, session

from scoring.checks import A01_broken_access_control as a01
from scoring.config import load_config
from scoring.tests.test_account_probes import _Ctx

_CFG = {**(load_config().get("dynamic.checks.idor_write") or {}), "retry_wait_seconds": 0}
_CHECK = next(c for c in a01.CHECKS if c.id == "idor_write")


def _board(owner_check=True, put_only=False, deny_status=403, flaky_detail=0, dead=False,
           crash_missing=False, delete_open=False, limit_after_delete=False, search_empty=False,
           soft_missing=False, limit_status=429):
    """Posts and comments. ``owner_check`` False lets anyone edit or delete.
    ``put_only``: no PATCH route (405). ``deny_status``: what a refused write answers.
    ``flaky_detail``: the post page answers 500 this many times after a post delete
    request, allowed or not (sqlite locked: search fails with it). ``dead``:
    after a post delete request the app stops answering (the grader's reads get no
    response). ``crash_missing``: the post page answers 500 for a post that no
    longer exists. ``delete_open``: edits are refused but anyone may delete a post.
    ``limit_after_delete``: a limiter answers 429 to every read after a post delete.
    ``search_empty``: search answers but finds nothing. ``soft_missing``: the post
    page answers 200 "글이 없습니다" for a missing post. ``limit_status``: the
    status of the limiter's page."""
    app = Flask(__name__)
    app.secret_key = secrets.token_hex(16)
    users, posts, comments, seq = {}, {}, {}, [0]
    flaky = [0]
    limited = [False]

    def body():
        return request.get_json(silent=True) or {}

    def me():
        return session.get("uid")

    def nid():
        seq[0] += 1
        return seq[0]

    @app.post("/signup")
    def signup():
        d = body()
        uid = nid()
        users[uid] = d
        session["uid"] = uid
        return jsonify(id=uid), 201

    @app.post("/login")
    def login():
        d = body()
        uid = next((i for i, u in users.items() if u["username"] == d.get("username")), None)
        if uid is None:
            return jsonify(error="bad"), 401
        session["uid"] = uid
        return jsonify(id=uid)

    @app.post("/posts")
    def create():
        pid = nid()
        posts[pid] = dict(author=me(), title=body()["title"], content=body()["content"])
        return jsonify(id=pid), 201

    @app.get("/search")
    def search():
        q = request.args.get("q", "")
        if limited[0]:
            return "Too Many Requests", limit_status
        if flaky[0] > 0:
            flaky[0] -= 1
            return "database is locked", 500
        if search_empty:
            return "<p>no results</p>"
        return "".join(f"<li>{p['title']}</li>" for p in posts.values() if q in p["title"])

    @app.get("/posts/<int:pid>")
    def detail(pid):
        if limited[0]:
            return "Too Many Requests", limit_status
        if flaky[0] > 0:
            flaky[0] -= 1
            return "database is locked", 500
        if soft_missing and pid not in posts:
            return "<p>글이 없습니다</p>", 200
        if crash_missing and pid not in posts:
            return "TypeError: 'NoneType' object is not subscriptable", 500
        p = posts.get(pid) or abort(404)
        notes = "".join(f'<p><a href="/comments/{c}">{v["content"]}</a></p>'
                        for c, v in comments.items() if v["post"] == pid)
        return f"<h1>{p['title']}</h1><div>{p['content']}</div>{notes}"

    @app.post("/posts/<int:pid>/comments")
    def comment(pid):
        cid = nid()
        comments[cid] = dict(post=pid, author=me(), content=body()["content"])
        return jsonify(id=cid), 201

    def allowed(obj):
        return not owner_check or obj["author"] == me()

    def edit(store, oid):
        obj = store.get(oid) or abort(404)
        if not allowed(obj):
            return jsonify(error="forbidden"), deny_status
        obj.update({k: v for k, v in body().items() if k in ("title", "content")})
        return jsonify(ok=True)

    @app.route("/posts/<int:pid>", methods=["PATCH", "PUT", "DELETE"])
    @app.route("/comments/<int:pid>", methods=["PATCH", "PUT", "DELETE"])
    def write(pid):
        store = posts if request.path.startswith("/posts") else comments
        if request.method == "PATCH" and put_only:
            return "method not allowed", 405
        if request.method != "DELETE":
            return edit(store, pid)
        if store is posts:
            flaky[0] = flaky_detail
            app.config["dead"] = dead
            limited[0] = limit_after_delete
        obj = store.get(pid) or abort(404)
        if not allowed(obj) and not (delete_open and store is posts):
            return jsonify(error="forbidden"), deny_status
        store.pop(pid)
        return jsonify(ok=True)

    return app


class _WriteCtx(_Ctx):
    def __init__(self, app):
        super().__init__(app, [])

    def patch(self, sess, path, data):
        return self._send("PATCH", sess, path, data)

    def put(self, sess, path, data):
        return self._send("PUT", sess, path, data)

    def get(self, sess, path, **kw):
        if self.app.config.get("dead"):
            return None
        return super().get(sess, path, **kw)


def _run(**board):
    return a01.dynamic_idor_write(_CHECK, _WriteCtx(_board(**board)), _CFG)


def test_owner_checked_writes_pass():
    r = _run()
    assert not r.skipped and r.passed, r.penalty_reasons


@pytest.mark.parametrize("deny", [403, 404, 200])
def test_refused_write_passes_whatever_the_status(deny):
    # 404 to hide the post (RFC 9110 allows it) or a 200 that changes nothing.
    r = _run(deny_status=deny)
    assert not r.skipped and r.passed, r.penalty_reasons


def test_anyone_can_edit_and_delete_fails():
    r = _run(owner_check=False)
    assert not r.skipped and not r.passed and r.score == 0
    assert "남의 댓글 수정 PATCH" in r.evidence[0]


def test_put_only_app_reports_put():
    r = _run(owner_check=False, put_only=True)
    assert not r.passed and "PUT /comments/" in r.evidence[0]


def test_post_page_500_after_a_refused_delete_is_not_a_delete():
    # The refused delete leaves the post; the page then answers 500 twice under load.
    r = _run(flaky_detail=2)
    assert not r.skipped and r.passed, r.penalty_reasons


def test_reasons_have_no_parentheses():
    r = _run(owner_check=False)
    assert not any(ch in r.penalty_reasons[0] for ch in "()")


@pytest.mark.parametrize("board", [dict(flaky_detail=99), dict(dead=True)])
def test_post_page_that_never_answers_after_a_delete_is_undecided(board):
    # Measured on a real app paused after DELETE: a vulnerable delete read as "kept".
    r = _run(owner_check=True, **board)
    assert r.skipped, (r.score, r.evidence)


def test_proven_edit_still_fails_when_the_page_then_stops_answering():
    r = _run(owner_check=False, dead=True)
    assert not r.skipped and not r.passed and "남의 댓글 수정" in r.evidence[0]


def test_delete_whose_post_page_then_crashes_fails():
    # Only deleting is open. The row is gone and the detail view crashes on it;
    # search still answers, finds the untouched post and not this one.
    r = _run(delete_open=True, crash_missing=True)
    assert not r.skipped and not r.passed
    assert "검색에서 사라짐" in r.evidence[0], r.evidence


def test_refused_delete_with_a_crashing_missing_page_passes():
    r = _run(crash_missing=True)
    assert not r.skipped and r.passed, r.penalty_reasons


def test_busy_app_after_a_refused_delete_is_undecided_not_a_delete():
    # Post page and search both fail while the app is locked: no proof either way.
    r = _run(flaky_detail=99, crash_missing=True)
    assert r.skipped, (r.score, r.evidence)


def test_lock_that_outlasts_the_retries_is_settled_by_search():
    # The post page fails for all 3 retries after the refused delete; search then
    # answers and still finds the post (an on-off lock cannot fake a delete).
    r = _run(flaky_detail=3)
    assert not r.skipped and r.passed, r.penalty_reasons


def test_lock_that_outlasts_the_retries_still_catches_a_delete():
    r = _run(delete_open=True, flaky_detail=3)
    assert not r.skipped and not r.passed
    assert "남의 글 삭제" in r.evidence[0], r.evidence


@pytest.mark.parametrize("delete_open", [False, True])
def test_limiter_answer_after_the_delete_is_undecided(delete_open):
    # A 429 page is not the post: neither "still there" nor "deleted".
    r = _run(delete_open=delete_open, limit_after_delete=True)
    assert r.skipped, (r.score, r.evidence)


@pytest.mark.parametrize("delete_open", [False, True])
def test_search_finding_nothing_proves_nothing(delete_open):
    # Search answers but finds neither post: it cannot tell a delete from a miss.
    r = _run(flaky_detail=3, search_empty=True, delete_open=delete_open)
    assert r.skipped, (r.score, r.evidence)


def test_soft_missing_page_after_a_delete_is_proven_by_search():
    r = _run(delete_open=True, soft_missing=True)
    assert not r.skipped and not r.passed and "검색에서 사라짐" in r.evidence[0], r.evidence


@pytest.mark.parametrize("delete_open", [False, True])
def test_limiter_page_with_200_after_the_delete_is_undecided(delete_open):
    # A 200 "Too Many Requests" page has no post on it: not a delete by itself.
    r = _run(delete_open=delete_open, limit_after_delete=True, limit_status=200)
    assert r.skipped, (r.score, r.evidence)
