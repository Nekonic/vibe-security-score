"""Unit tests for the comment_authorization (BOLA) probe against a fake board.

Pins FP/FN WITHOUT Docker: a defended app scores 100, an app that lets userB edit
or delete userA's comment scores 0, and an app with no comment edit/delete feature
(or a broken owner control) SKIPS — never accuses. Verdicts are read from a fresh
GET of the post detail, never the write response.
"""
from __future__ import annotations

import re

from scoring.checks import A01_broken_access_control as a01

_CHECK = next(c for c in a01.CHECKS if c.id == "comment_authorization")
_POST_RE = re.compile(r"^/posts/(\d+)$")
_CMT_RE = re.compile(r"^/comments/(\d+)$")
_CMT_COL_RE = re.compile(r"^/posts/(\d+)/comments$")


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
        self.phone = "010" + sid * 8
        self.name = sid
        self.is_admin = False


class _FakeBoard:
    """Posts + comments with per-verb comment authorization knobs."""

    def __init__(self, *, enforce_edit=True, enforce_delete=True,
                 has_edit=True, has_delete=True, id_in_json=True,
                 id_in_html=True, id_in_detail_json=False):
        self.userA = _Acct("a")
        self.userB = _Acct("b")
        self.admin = None
        self.enforce_edit = enforce_edit
        self.enforce_delete = enforce_delete
        self.has_edit = has_edit
        self.has_delete = has_delete
        self.id_in_json = id_in_json          # create response carries the comment id
        self.id_in_html = id_in_html          # post-detail HTML renders a /comments/<id> link
        self.id_in_detail_json = id_in_detail_json  # post-detail JSON exposes comments[].id
        self._posts: dict[int, dict] = {}
        self._comments: dict[int, dict] = {}   # cid -> {post, owner, content}
        self._np = 1
        self._nc = 1

    def post(self, sess, path, data):
        if path == "/posts":
            pid = self._np
            self._np += 1
            self._posts[pid] = {"owner": sess, "content": data["content"]}
            return _Resp(201, json={"id": pid}) if self.id_in_json else _Resp(201, "created")
        m = _CMT_COL_RE.match(path)
        if m:
            pid = int(m.group(1))
            if pid not in self._posts:
                return _Resp(404)
            cid = self._nc
            self._nc += 1
            self._comments[cid] = {"post": pid, "owner": sess, "content": data["content"]}
            return _Resp(201, json={"id": cid}) if self.id_in_json else _Resp(201, "created")
        return _Resp(404)

    def _detail(self, pid: int) -> str:
        parts = [self._posts[pid]["content"]] if pid in self._posts else []
        for cid, c in sorted(self._comments.items()):
            if c["post"] == pid:
                # An app may render comments as plain text (no edit/delete link) — then
                # the id is only pinnable via the JSON detail (id_in_detail_json).
                if self.id_in_html:
                    parts.append(f'<div><a href="/comments/{cid}">{c["content"]}</a></div>')
                else:
                    parts.append(f'<div>{c["content"]}</div>')
        return " ".join(parts)

    def _detail_json(self, pid: int) -> dict:
        return {
            "post": {"id": pid, "content": self._posts[pid]["content"]},
            "comments": [
                {"id": cid, "content": c["content"]}
                for cid, c in sorted(self._comments.items()) if c["post"] == pid
            ],
        }

    def get(self, sess, path, **kw):
        wants_json = "json" in str((kw.get("headers") or {}).get("Accept", "")).lower()
        if path == "/posts":
            body = "".join(
                f'<a href="/posts/{i}">{p["content"]}</a>' for i, p in sorted(self._posts.items())
            )
            return _Resp(200, body)
        m = _POST_RE.match(path)
        if m:
            pid = int(m.group(1))
            if pid not in self._posts:
                return _Resp(404)
            if wants_json and self.id_in_detail_json:
                return _Resp(200, json=self._detail_json(pid))
            return _Resp(200, self._detail(pid))
        return _Resp(404)

    def _write_comment(self, sess, path, data, enforce, present):
        m = _CMT_RE.match(path)
        if not m or not present:
            return _Resp(405)
        cid = int(m.group(1))
        c = self._comments.get(cid)
        if c is None:
            return _Resp(404)
        if enforce and c["owner"] != sess:
            return _Resp(403)
        return cid

    def put(self, sess, path, data):
        r = self._write_comment(sess, path, data, self.enforce_edit, self.has_edit)
        if isinstance(r, _Resp):
            return r
        self._comments[r]["content"] = data["content"]
        return _Resp(200, "ok")

    patch = put

    def delete(self, sess, path, data=None):
        r = self._write_comment(sess, path, data or {}, self.enforce_delete, self.has_delete)
        if isinstance(r, _Resp):
            return r
        del self._comments[r]
        return _Resp(200, "deleted")


def _run(app):
    return a01.dynamic_comment_authorization(_CHECK, app, {})


def test_defended_scores_100():
    r = _run(_FakeBoard())
    assert r.passed is True and r.score == 100.0 and r.skipped is False


def test_userB_edit_lands_scores_0():
    r = _run(_FakeBoard(enforce_edit=False))
    assert r.passed is False and r.score == 0.0
    assert any("수정" in x for x in r.penalty_reasons)


def test_userB_delete_lands_scores_0():
    r = _run(_FakeBoard(enforce_delete=False))
    assert r.passed is False and r.score == 0.0
    assert any("삭제" in x for x in r.penalty_reasons)


def test_no_comment_edit_or_delete_feature_skips():
    r = _run(_FakeBoard(has_edit=False, has_delete=False))
    assert r.skipped is True  # no owner control on either surface


def test_delete_only_app_still_judged():
    # edit absent (skip) but delete present & enforced -> defended, not skip.
    r = _run(_FakeBoard(has_edit=False))
    assert r.passed is True and r.score == 100.0


def test_comment_id_discovered_from_html():
    # create response carries no id => probe finds it via the /comments/<id> link.
    r = _run(_FakeBoard(id_in_json=False))
    assert r.passed is True and r.score == 100.0


def test_comment_id_discovered_from_json_detail():
    # The app-#2 shape: no id in the create response, comments rendered as plain text
    # (no /comments/<id> link in HTML), but the JSON post detail exposes comments[].id.
    # A defended app MUST be judged (not skipped as "no comment feature").
    r = _run(_FakeBoard(id_in_json=False, id_in_html=False, id_in_detail_json=True))
    assert r.skipped is False
    assert r.passed is True and r.score == 100.0


def test_comment_bola_caught_when_id_only_in_json_detail():
    # Same id-only-in-JSON shape but a BROKEN app (userB can delete userA's comment):
    # the fix must let the probe reach the vulnerability, not skip past it.
    r = _run(_FakeBoard(enforce_delete=False, id_in_json=False,
                        id_in_html=False, id_in_detail_json=True))
    assert r.passed is False and r.score == 0.0
    assert any("삭제" in x for x in r.penalty_reasons)


def test_missing_account_skips():
    app = _FakeBoard()
    app.userB = None
    r = _run(app)
    assert r.skipped is True
