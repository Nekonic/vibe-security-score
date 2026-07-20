"""Unit tests for the BOLA probe (object_authorization) against a fake board app.

The probe's verdict logic is exercised deterministically with an in-memory app so
the false-positive/false-negative behavior is pinned WITHOUT Docker: a defended app
must score 100, an app that lets userB edit or delete userA's post must score 0, and
an app with no edit feature (or a broken owner control) must SKIP, never accuse.
"""
from __future__ import annotations

import re

from scoring.checks import A01_broken_access_control as a01

_CHECK = next(c for c in a01.CHECKS if c.id == "object_authorization")
_POST_RE = re.compile(r"^/posts/(\d+)$")


class _Resp:
    def __init__(self, status: int, text: str = "", json=None):
        self.status_code = status
        self._text = text
        self._json = json

    @property
    def text(self) -> str:
        return self._text

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


class _Acct:
    def __init__(self, sid: str):
        self.session = sid
        self.user_id = None
        self.email = f"{sid}@test.com"
        self.name = sid
        self.is_admin = False


class _FakeApp:
    """A minimal board: posts keyed by id, with per-verb authorization knobs."""

    def __init__(self, *, enforce_edit=True, enforce_delete=True,
                 has_edit=True, has_delete=True, id_in_json=True):
        self.userA = _Acct("a")
        self.userB = _Acct("b")
        self.admin = None
        self.enforce_edit = enforce_edit
        self.enforce_delete = enforce_delete
        self.has_edit = has_edit
        self.has_delete = has_delete
        self.id_in_json = id_in_json
        self._posts: dict[int, dict] = {}
        self._next = 1

    def post(self, sess, path, data):
        if path != "/posts":
            return _Resp(404)
        pid = self._next
        self._next += 1
        self._posts[pid] = {"owner": sess, "title": data["title"], "content": data["content"]}
        if self.id_in_json:
            return _Resp(201, json={"id": pid})
        return _Resp(201, text="created")

    def get(self, sess, path):
        if path == "/posts":
            body = "".join(
                f'<a href="/posts/{i}">{p["content"]}</a>' for i, p in sorted(self._posts.items())
            )
            return _Resp(200, text=body)
        m = _POST_RE.match(path)
        if m:
            p = self._posts.get(int(m.group(1)))
            return _Resp(200, text=f'{p["title"]} {p["content"]}') if p else _Resp(404)
        return _Resp(404)

    def _write(self, sess, path, data, enforce, present):
        m = _POST_RE.match(path)
        if not m or not present:
            return _Resp(405)
        pid = int(m.group(1))
        p = self._posts.get(pid)
        if p is None:
            return _Resp(404)
        if enforce and p["owner"] != sess:
            return _Resp(403)
        return pid

    def put(self, sess, path, data):
        r = self._write(sess, path, data, self.enforce_edit, self.has_edit)
        if isinstance(r, _Resp):
            return r
        self._posts[r].update(title=data["title"], content=data["content"])
        return _Resp(200, text="ok")

    patch = put

    def delete(self, sess, path, data=None):
        r = self._write(sess, path, data or {}, self.enforce_delete, self.has_delete)
        if isinstance(r, _Resp):
            return r
        del self._posts[r]
        return _Resp(200, text="deleted")


def _run(app):
    return a01.dynamic_object_authorization(_CHECK, app, {})


def test_defended_scores_100():
    r = _run(_FakeApp())
    assert r.passed is True and r.score == 100.0 and r.skipped is False


def test_userB_edit_lands_scores_0():
    r = _run(_FakeApp(enforce_edit=False))
    assert r.passed is False and r.score == 0.0 and r.skipped is False
    assert any("수정" in x for x in r.penalty_reasons)


def test_userB_delete_lands_scores_0():
    r = _run(_FakeApp(enforce_delete=False))
    assert r.passed is False and r.score == 0.0
    assert any("삭제" in x for x in r.penalty_reasons)


def test_no_edit_feature_skips():
    r = _run(_FakeApp(has_edit=False))
    assert r.skipped is True  # owner control cannot be established


def test_id_discovery_path_defended():
    # create response carries no id => probe must find it via the listing.
    r = _run(_FakeApp(id_in_json=False))
    assert r.passed is True and r.score == 100.0


def test_missing_account_skips():
    app = _FakeApp()
    app.userB = None
    r = _run(app)
    assert r.skipped is True
