"""Live app preview: prefix rewriting + the login-only proxy view. Docker and the
app container are mocked; the proxied app's response is canned."""
from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

from django.test import Client, TestCase
from django.urls import reverse
from requests.structures import CaseInsensitiveDict

from submissions import preview_views, state
from submissions.models import Submission
from submissions.preview_views import proxied_cookie, rewrite_body, rewrite_location

from .test_ui import _make_done_submission, _mk_user

P = "/submissions/7/app"


class RewriteTests(TestCase):
    def test_root_relative_html_urls_get_prefix(self):
        html = (b'<a href="/posts">x</a><form action=\'/login\'><img src=/static/a.png>'
                b'<a href="//cdn.example/x">c</a><a href="https://e.com/">e</a><a href="rel">r</a>'
                b'<div style="background:url(/static/bg.png)"></div>')
        out = rewrite_body(html, "text/html; charset=utf-8", P)
        self.assertIn(b'href="/submissions/7/app/posts"', out)
        self.assertIn(b"action='/submissions/7/app/login'", out)
        self.assertIn(b"src=/submissions/7/app/static/a.png", out)
        self.assertIn(b"url(/submissions/7/app/static/bg.png)", out)
        self.assertIn(b'href="//cdn.example/x"', out)
        self.assertIn(b'href="https://e.com/"', out)
        self.assertIn(b'href="rel"', out)

    def test_board_js_targets_get_prefix(self):
        # static/board.js sends PATCH/DELETE to data-url and then goes to data-next.
        html = b'<form data-method="PATCH" data-url="/posts/1"><button data-next="/posts">'
        out = rewrite_body(html, "text/html", P)
        self.assertIn(b'data-url="/submissions/7/app/posts/1"', out)
        self.assertIn(b'data-next="/submissions/7/app/posts"', out)

    def test_non_html_untouched(self):
        self.assertEqual(rewrite_body(b'{"u": "/posts"}', "application/json", P), b'{"u": "/posts"}')

    def test_location(self):
        self.assertEqual(rewrite_location("/posts/3?x=1", P), P + "/posts/3?x=1")
        self.assertEqual(rewrite_location("http://127.0.0.1:5000/login", P), P + "/login")
        self.assertEqual(rewrite_location("https://example.com/x", P), "https://example.com/x")
        self.assertEqual(rewrite_location("detail", P), "detail")

    def test_cookie_rescoped_and_secure_dropped_over_http(self):
        m = proxied_cookie("session=eyJ1IjoxfQ.Zx.abc; HttpOnly; Path=/; Secure; SameSite=None", P, False)
        out = m.OutputString()
        self.assertIn("session=eyJ1IjoxfQ.Zx.abc", out)
        self.assertIn(f"Path={P}/", out)
        self.assertIn("HttpOnly", out)
        self.assertNotIn("Secure", out)
        self.assertNotIn("SameSite", out)

    def test_cookie_keeps_secure_over_https(self):
        out = proxied_cookie("session=v; Path=/; Secure; SameSite=Lax", P, True).OutputString()
        self.assertIn("Secure", out)
        self.assertIn("SameSite=Lax", out)


def _app_response(status=200, body=b"", ctype="text/html", headers=None, cookies=()):
    h = CaseInsensitiveDict({"Content-Type": ctype, **(headers or {})})
    raw = SimpleNamespace(headers=SimpleNamespace(getlist=lambda name: list(cookies)))
    return SimpleNamespace(status_code=status, content=body, headers=h, raw=raw)


@mock.patch.object(preview_views.preview_session, "reap_idle", lambda *a, **k: None)
@mock.patch.object(preview_views.preview_session, "touch", lambda *a, **k: None)
class ProxyViewTests(TestCase):
    def setUp(self):
        self.sub = _make_done_submission()
        self.sub.workdir = "/tmp/app"
        state.save_fields(self.sub, "workdir")
        self.url = reverse("submissions:app_preview", kwargs={"pk": self.sub.pk})
        preview_views.preview_session._PORTS.clear()
        self.addCleanup(preview_views.preview_session._PORTS.clear)

    def _cache_port(self, port):
        import time
        preview_views.preview_session._PORTS[self.sub.pk] = (port, time.time())

    def test_cached_port_forwards_without_docker(self):
        self.client.force_login(_mk_user())
        self._cache_port(40555)
        app = _app_response(body=b"<h1>board</h1>")
        with mock.patch.object(preview_views.preview_session, "container_state") as cs, \
             mock.patch.object(preview_views.preview_session, "wait_ready") as wr, \
             mock.patch.object(preview_views.requests, "request", return_value=app) as req:
            r = self.client.get(self.url + "posts")
        cs.assert_not_called()
        wr.assert_not_called()
        req.assert_called_once()
        self.assertEqual(req.call_args.args[1], "http://127.0.0.1:40555/posts")
        self.assertContains(r, "board")

    def test_stale_cached_port_rechecks_docker_and_resends_same_body(self):
        import requests as _rq
        self.client.force_login(_mk_user())
        self._cache_port(40555)
        app = _app_response(body=b"<h1>ok</h1>")
        with mock.patch.object(preview_views.preview_session, "container_state", return_value="running") as cs, \
             mock.patch.object(preview_views.preview_session, "wait_ready", return_value=40666), \
             mock.patch.object(preview_views.requests, "request",
                               side_effect=[_rq.ConnectionError("refused"), app]) as req:
            r = self.client.post(self.url + "posts", data={"title": "t"})
        cs.assert_called_once()
        self.assertEqual([c.args[1] for c in req.call_args_list],
                         ["http://127.0.0.1:40555/posts", "http://127.0.0.1:40666/posts"])
        first, second = (c.kwargs["data"] for c in req.call_args_list)
        self.assertEqual(first, second)
        self.assertIn(b'name="title"', second)
        self.assertNotIn(self.sub.pk, preview_views.preview_session._PORTS)
        self.assertContains(r, "ok")

    def test_requires_login(self):
        r = self.client.get(self.url)
        self.assertEqual(r.status_code, 302)
        self.assertIn("login", r["Location"])

    def test_failed_submission_is_refused(self):
        self.client.force_login(_mk_user())
        sub = Submission.objects.create(participant="p", prompt="x")
        state.to_failed(sub, "boom")
        r = self.client.get(reverse("submissions:app_preview", kwargs={"pk": sub.pk}))
        self.assertContains(r, "열 수 없는 제출", status_code=503)

    def test_generating_proxies_codex_self_test_server(self):
        self.client.force_login(_mk_user())
        sub = Submission.objects.create(participant="p", prompt="x")
        state.to_generating(sub)
        url = reverse("submissions:app_preview", kwargs={"pk": sub.pk})
        with mock.patch("codex_runner.activity.read_preview_port", return_value=None):
            self.assertContains(self.client.get(url), "서버 띄우는 중...", status_code=503)
        app = _app_response(body=b"<h1>board</h1>")
        with mock.patch("codex_runner.activity.read_preview_port", return_value=41999), \
             mock.patch.object(preview_views.requests, "request", return_value=app) as req:
            r = self.client.get(url + "posts")
        self.assertEqual(req.call_args.args[1], "http://127.0.0.1:41999/posts")
        self.assertContains(r, "board")

    def test_first_visit_boots_container_then_serves_app_without_loading_page(self):
        self.client.force_login(_mk_user())
        app = _app_response(body=b"<h1>board</h1>")
        with mock.patch.object(preview_views.preview_session, "container_state", return_value="missing"), \
             mock.patch.object(preview_views.preview_session, "start", return_value={"ok": True}) as start, \
             mock.patch.object(preview_views.preview_session, "wait_ready", return_value=40123), \
             mock.patch.object(preview_views.requests, "request", return_value=app):
            r = self.client.get(self.url)
        start.assert_called_once()
        self.assertContains(r, "board")

    def test_proxies_with_rewrites_and_strips_grader_cookies(self):
        # Real CSRF enforcement: the app's own form POST (no Django token) must pass.
        self.client = Client(enforce_csrf_checks=True)
        self.client.force_login(_mk_user())
        self.client.cookies["session"] = "appcookie"
        self.client.cookies["csrftoken"] = "grader-csrf"
        app = _app_response(
            status=302, body=b'<a href="/posts">p</a>',
            headers={"Location": "/posts", "X-Frame-Options": "DENY", "X-App": "1",
                     "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'"},
            cookies=["session=new; Path=/; HttpOnly"],
        )
        with mock.patch.object(preview_views.preview_session, "container_state", return_value="running"), \
             mock.patch.object(preview_views.preview_session, "wait_ready", return_value=40123), \
             mock.patch.object(preview_views.requests, "request", return_value=app) as req:
            r = self.client.post(self.url + "login?next=a%20b", data={"username": "u"})
        method, target = req.call_args.args
        self.assertEqual((method, target), ("POST", "http://127.0.0.1:40123/login?next=a%20b"))
        sent = req.call_args.kwargs["headers"]
        self.assertEqual(sent["Cookie"], "session=appcookie")  # sessionid/csrftoken stripped
        self.assertEqual(r.status_code, 302)
        self.assertEqual(r["Location"], f"/submissions/{self.sub.pk}/app/posts")
        self.assertEqual(r["X-App"], "1")
        # Embeddable in the result page: app's framing ban relaxed to same-origin.
        self.assertEqual(r["X-Frame-Options"], "SAMEORIGIN")
        self.assertEqual(r["Content-Security-Policy"], "default-src 'self'")
        self.assertIn(f'href="/submissions/{self.sub.pk}/app/posts"'.encode(), r.content)
        self.assertEqual(r.cookies["session"]["path"], f"/submissions/{self.sub.pk}/app/")

    def test_exited_container_shows_logs_and_is_removed(self):
        self.client.force_login(_mk_user())
        with mock.patch.object(preview_views.preview_session, "container_state", return_value="running"), \
             mock.patch.object(preview_views.preview_session, "wait_ready", return_value="exited"), \
             mock.patch.object(preview_views.preview_session, "logs", return_value="ImportError: boom"), \
             mock.patch.object(preview_views.preview_session, "remove") as remove:
            r = self.client.get(self.url)
        remove.assert_called_once_with(self.sub.pk)
        self.assertContains(r, "ImportError: boom", status_code=503)


class AppLiveFlagTests(TestCase):
    def test_status_json_reports_app_live_only_while_generating_and_answering(self):
        sub = Submission.objects.create(participant="p", prompt="x")
        state.to_generating(sub)
        url = reverse("submissions:status_json", kwargs={"pk": sub.pk})
        with mock.patch("codex_runner.activity.read_preview_port", return_value=41999), \
             mock.patch("submissions.preview_session.answers", return_value=False):
            self.assertFalse(self.client.get(url).json()["app_live"])
        with mock.patch("codex_runner.activity.read_preview_port", return_value=41999), \
             mock.patch("submissions.preview_session.answers", return_value=True):
            self.assertTrue(self.client.get(url).json()["app_live"])
        done = _make_done_submission()
        self.assertFalse(self.client.get(
            reverse("submissions:status_json", kwargs={"pk": done.pk})).json()["app_live"])
