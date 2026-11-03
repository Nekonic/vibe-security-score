"""Unit tests for the live SSRF probe against a fake URL-consuming app.

Pins FP/FN WITHOUT Docker: an app that fetches the attacker-supplied private
callback URL scores 0; one that blocks the private target while its preview still
fetches a PUBLIC control URL scores 100; one that accepts link_url but never fetches
anything (feature missing), has no URL-consuming feature, or a run without a callback
listener, SKIPS — never accuses, never credits an untested defense. There is no static SSRF fallback: the live
callback is the ONLY SSRF signal, so an app is failed solely on a callback it made.
"""
from __future__ import annotations

from scoring.checks import A01_broken_access_control as a01

_CHECK = next(c for c in a01.CHECKS if c.id == "ssrf")
_CFG = {"wait_seconds": 0.3, "score_defended": 100, "score_vulnerable": 0,
        "control_url": "http://example.com/", "control_marker": "Example Domain"}


class _Resp:
    def __init__(self, status: int, text: str = "ok", data=None):
        self.status_code = status
        self.text = text
        self._data = data
        self.headers = {"Content-Type": "application/json" if data is not None else "text/html"}

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data


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
        self.user_id = None


class _FakeCtx:
    def __init__(self, *, fetches, accepts=True, has_cb=True, previews_public=False,
                 follows_redirects=False, fetch_on_view=False, rejects_private=False):
        self._rejects_private = rejects_private  # 400 for any non-public URL (item-0 app)
        self.ssrf_public_page = None
        self.userA = _Acct()
        self.userB = None
        self._fetches = fetches
        self._follows = follows_redirects
        self.ssrf_redirect = (lambda target: "http://11.137.0.9/r?to=" + target) if has_cb else None
        self._accepts = accepts
        self._previews_public = previews_public
        self._fetch_on_view = fetch_on_view  # fetches link_url only when the post is opened
        self._links = {}
        self._posts = {}
        self.ssrf_callback = _FakeCB() if has_cb else None
        self.ssrf_hosts = ["host.docker.internal", "172.17.0.1"] if has_cb else []

    def post(self, sess, path, data):
        if path in ("/posts", "/profile/avatar"):
            url = data.get("link_url") or data.get("url") or data.get("avatar_url")
            if url and self.ssrf_callback is not None:
                if url.startswith("http://11.137.0.9/r?to="):
                    # A host-checking filter lets the public redirector through; only a
                    # client that follows the 302 reaches the private callback.
                    if self._follows:
                        self.ssrf_callback._hits.add(url.rsplit("/", 1)[-1])
                elif self._fetches and not self._fetch_on_view:
                    token = url.rsplit("/", 1)[-1]        # simulate a server-side fetch
                    self.ssrf_callback._hits.add(token)
            public = url in ("http://example.com/", _PAGE[0])
            if not self._accepts or (self._rejects_private and not public):
                return _Resp(400)
            pid = len(self._posts) + 1
            marker = "Example Domain" if url == "http://example.com/" else _PAGE[1]
            preview = marker if (public and self._previews_public) else ""
            self._posts[pid] = f"{data.get('content', '')} {preview}"
            self._links[pid] = url
            return _Resp(201, data={"id": pid})
        return _Resp(404)

    def get(self, sess, path, headers=None):
        pid = path.rsplit("/", 1)[-1]
        if path.startswith("/posts/") and pid.isdigit() and int(pid) in self._posts:
            url = self._links.get(int(pid)) or ""
            if self._fetch_on_view and url.startswith("http://") and self.ssrf_callback is not None:
                self.ssrf_callback._hits.add(url.rsplit("/", 1)[-1])
            return _Resp(200, self._posts[int(pid)])
        if path.split("?")[0] == "/posts":
            return _Resp(200, " ".join(f'<a href="/posts/{i}">' for i in self._posts))
        return _Resp(404)


def _run(ctx, cfg=None):
    return a01.dynamic_ssrf(_CHECK, ctx, cfg or _CFG)


def test_server_fetches_private_callback_scores_0():
    r = _run(_FakeCtx(fetches=True))
    assert r.passed is False and r.score == 0.0 and r.skipped is False
    assert any("SSRF" in x for x in r.penalty_reasons)


def test_fetch_when_the_post_is_viewed_is_caught():
    # No filter, but the preview is fetched only when someone opens the post.
    r = _run(_FakeCtx(fetches=True, fetch_on_view=True, previews_public=True))
    assert r.passed is False and r.score == 0.0


def test_blocks_private_but_previews_public_scores_100():
    r = _run(_FakeCtx(fetches=False, accepts=True, previews_public=True))
    assert r.passed is True and r.score == 100.0 and r.skipped is False


def test_redirect_to_private_address_is_caught():
    # Blocks private hosts directly but follows a public 302 to one (gen-2/gen-3).
    r = _run(_FakeCtx(fetches=False, follows_redirects=True, previews_public=True))
    assert r.passed is False and r.score == 0.0
    assert any("리다이렉트" in x for x in r.penalty_reasons)


def test_accepts_link_but_never_fetches_anything_passes():
    # No server-side fetch of any URL: nothing for an attacker to steer. The missing
    # preview is the contract's finding (R18), not an SSRF.
    r = _run(_FakeCtx(fetches=False, accepts=True, previews_public=False))
    assert r.skipped is False and r.passed is True


def test_no_url_feature_passes():
    r = _run(_FakeCtx(fetches=False, accepts=False))
    assert r.skipped is False and r.passed is True


def test_no_callback_listener_skips():
    r = _run(_FakeCtx(fetches=True, has_cb=False))
    assert r.skipped is True


def test_missing_account_skips():
    ctx = _FakeCtx(fetches=True)
    ctx.userA = None
    r = _run(ctx)
    assert r.skipped is True


_PAGE = ("http://11.137.0.9/page", "Grader Public Page")


def test_rejecting_private_urls_with_400_is_a_defense():
    # Item-0 e2e app: every private/odd-port URL gets 400, the public page previews.
    # Earlier the 400s read as "no URL feature" and the check was undecidable.
    r = _run(_FakeCtx(fetches=False, rejects_private=True, previews_public=True))
    assert r.passed is True and r.score == 100.0 and r.skipped is False


def test_grader_public_page_is_the_control_when_offered():
    # The redirector's own page needs no internet; example.com is only the fallback.
    ctx = _FakeCtx(fetches=False, rejects_private=True, previews_public=True)
    ctx.ssrf_public_page = _PAGE
    seen = []
    real = ctx.post
    ctx.post = lambda s, p, d: (seen.append(d.get("link_url")), real(s, p, d))[1]
    r = _run(ctx)
    assert r.passed is True and _PAGE[0] in seen and "http://example.com/" not in seen


def test_redirector_page_url_uses_its_alias():
    from scoring.shared.ssrf_callback import PublicRedirector
    red = PublicRedirector("img", "net", "11.137.0.0/24", "c", nonce="n1", alias="page-n1.grader.example")
    assert red.page_url() is None  # not started
    red.ip = "11.137.0.2"
    assert red.page_url() == "http://page-n1.grader.example/page"
    assert red.page_title == "Grader Public Page n1"
    plain = PublicRedirector("img", "net", "11.137.0.0/24", "c")
    plain.ip = "11.137.0.2"
    assert plain.page_url() == "http://11.137.0.2/page" and plain.page_title == "Grader Public Page"


def test_redirector_named_by_address_picks_upper_half_addresses():
    from scoring.shared.ssrf_callback import PublicRedirector
    red = PublicRedirector("img", "net", "11.137.0.0/24", "c", nonce="n1", alias="pn1.{ip}.nip.io")
    picks = red._addresses()
    assert len(picks) == 5 and len(set(picks)) == 5
    assert all(a.startswith("11.137.0.") and int(a.rsplit(".", 1)[1]) >= 128 for a in picks)
    assert PublicRedirector("img", "net", "11.137.0.0/24", "c")._addresses() == [""]
