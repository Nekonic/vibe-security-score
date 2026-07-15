"""Part 1 web UI tests — submit flow, status polling, result screen, and the
security-by-design rule that checks are not disclosed before grading.

Fixtures are fabricated directly (no Codex/Docker): a graded submission is
produced by driving the state machine with a canned report.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import tempfile
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from submissions import state
from submissions.models import Submission
from submissions.views import _default_prompt


def _make_done_submission() -> Submission:
    sub = Submission.objects.create(participant="tester", prompt="게시판 만들어줘")
    state.to_queued(sub)
    report = {
        "final_score": 62.5,
        "grade": "통과",
        "pass_fail": "PASS",
        "findings": [
            {
                "check_id": "hardcoded_secret", "category": "static",
                "label": "하드코딩 시크릿", "score": 0.0, "weight": 12.0,
                "passed": False, "skipped": False, "tool": "",
                "penalty_reasons": ["app.py:23 SECRET_KEY 하드코딩"], "evidence": [],
            },
            {
                "check_id": "functional", "category": "dynamic",
                "label": "기능 게이트", "score": 100.0, "weight": 10.0,
                "passed": True, "skipped": False, "tool": "",
                "penalty_reasons": [], "evidence": [],
            },
            {
                "check_id": "gitleaks_secrets", "category": "static",
                "label": "gitleaks", "score": 0.0, "weight": 0.0,
                "passed": False, "skipped": True, "tool": "gitleaks",
                "penalty_reasons": ["검사 생략(도구 미설치)"], "evidence": [],
            },
        ],
    }
    state.to_done(sub, report)
    return sub


def _mk_user(username="viewer", staff=False):
    """An operator-created account. Login gates SUBMITTING, not viewing."""
    return get_user_model().objects.create_user(
        username=username, password="pw-Compl3x!23", is_staff=staff
    )


class SubmitGateTests(TestCase):
    def test_pages_are_viewable_without_login(self):
        # Pages (for the booth screen) are public; only submitting is gated.
        sub = _make_done_submission()
        self.assertEqual(self.client.get(reverse("submissions:submit")).status_code, 200)
        self.assertEqual(
            self.client.get(reverse("submissions:result", kwargs={"pk": sub.pk})).status_code, 200
        )

    def test_submit_form_hidden_when_anonymous(self):
        body = self.client.get(reverse("submissions:submit")).content.decode()
        self.assertNotIn("<textarea", body)          # no form
        self.assertNotIn("제출하고 채점받기", body)   # no submit button
        self.assertIn("로그인", body)                 # navbar login link is present

    def test_submit_post_requires_login(self):
        resp = self.client.post(
            reverse("submissions:submit"), {"prompt": "x", "nickname": "n"}
        )
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/login/", resp.url)
        self.assertEqual(Submission.objects.count(), 0)  # nothing enqueued

    def test_login_page_is_reachable_and_has_no_signup(self):
        resp = self.client.get(reverse("login"))
        self.assertEqual(resp.status_code, 200)
        self.assertIn("로그인", resp.content.decode())
        self.assertNotIn("회원가입", resp.content.decode())


class SubmitPageTests(TestCase):
    def setUp(self):
        self.client.force_login(_mk_user())

    def test_get_prefills_prompt_from_config_file(self):
        resp = self.client.get(reverse("submissions:submit"))
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        # The textarea is prefilled with the config default prompt.
        self.assertIn("<textarea", body)
        # A distinctive line from config/default_prompt.md must be present.
        self.assertIn("게시판", _default_prompt())
        self.assertIn(_default_prompt().strip().splitlines()[0], body)

    def test_submit_combines_system_prompt_with_user_prompt(self):
        resp = self.client.post(
            reverse("submissions:submit"),
            {"prompt": "나만의 프롬프트", "nickname": "alice"},
        )
        sub = Submission.objects.get()
        # The stored prompt = fixed system prompt + the participant's prompt.
        self.assertIn("게시판", sub.prompt)          # from the fixed system prompt
        self.assertIn("나만의 프롬프트", sub.prompt)   # participant input
        self.assertEqual(sub.status, Submission.Status.QUEUED)
        self.assertEqual(sub.participant, "alice")
        self.assertRedirects(resp, reverse("submissions:result", kwargs={"pk": sub.pk}))

    def test_empty_prompt_rejected(self):
        resp = self.client.post(reverse("submissions:submit"), {"prompt": "   "})
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(Submission.objects.count(), 0)

    def test_submit_page_does_not_disclose_security_checks(self):
        body = self.client.get(reverse("submissions:submit")).content.decode().lower()
        # None of the grading vocabulary may appear before grading.
        for term in ["idor", "xss", "타이포스쿼팅", "하드코딩", "감점", "취약", "csrf 검사"]:
            self.assertNotIn(term.lower(), body, f"submit page leaked check term: {term}")


class StatusAndResultTests(TestCase):
    def setUp(self):
        self.client.force_login(_mk_user())

    def test_status_json_reports_stage_and_queue_position(self):
        sub = Submission.objects.create(participant="p", prompt="x")
        state.to_queued(sub)
        data = self.client.get(
            reverse("submissions:status_json", kwargs={"pk": sub.pk})
        ).json()
        self.assertEqual(data["status"], "queued")
        self.assertEqual(data["stage_label"], "대기 중")
        self.assertEqual(data["queue_position"], 1)
        self.assertFalse(data["done"])

    def test_status_json_done_flags_terminal(self):
        sub = _make_done_submission()
        data = self.client.get(
            reverse("submissions:status_json", kwargs={"pk": sub.pk})
        ).json()
        self.assertTrue(data["done"])
        self.assertEqual(data["grade"], "통과")
        self.assertEqual(data["pass_fail"], "PASS")

    def test_result_page_renders_findings_and_grade(self):
        sub = _make_done_submission()
        body = self.client.get(
            reverse("submissions:result", kwargs={"pk": sub.pk})
        ).content.decode()
        # Grade + PASS badge
        self.assertIn("통과", body)
        self.assertIn("PASS", body)
        # A failing check with its penalty reason (감점 사유) is shown
        self.assertIn("하드코딩 시크릿", body)
        self.assertIn("app.py:23 SECRET_KEY 하드코딩", body)
        # A passing check shows the ✔ mark
        self.assertIn("기능 게이트", body)
        self.assertIn("✔", body)
        # Skipped aux tool (weight 0) is hidden on the participant result
        self.assertNotIn("gitleaks", body)

    def test_in_progress_page_shows_poller(self):
        sub = Submission.objects.create(participant="p", prompt="x")
        state.to_queued(sub)
        body = self.client.get(
            reverse("submissions:result", kwargs={"pk": sub.pk})
        ).content.decode()
        # poller wired: the resolved status URL + the poll loop are in the page
        status_url = reverse("submissions:status_json", kwargs={"pk": sub.pk})
        self.assertIn(status_url, body)
        self.assertIn("setTimeout(poll", body)
        self.assertIn("대기 중", body)

    def test_in_progress_page_has_live_activity_panel(self):
        sub = Submission.objects.create(participant="p", prompt="x")
        state.to_queued(sub)
        body = self.client.get(
            reverse("submissions:result", kwargs={"pk": sub.pk})
        ).content.decode()
        # codex-CLI style terminal panel (header title + live badge).
        self.assertIn("codex · 코드 생성", body)
        self.assertIn("ai-activity", body)
        self.assertIn(reverse("submissions:events_json", kwargs={"pk": sub.pk}), body)
        self.assertIn("pollEvents", body)


class GenerationEventsTests(TestCase):
    def setUp(self):
        self.client.force_login(_mk_user())
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.evpath = pathlib.Path(tmp) / "events.jsonl"
        patcher = mock.patch(
            "codex_runner.activity.events_path", lambda config, sid: self.evpath
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_events_endpoint_returns_items_after_since(self):
        sub = Submission.objects.create(
            participant="p", prompt="x", status=Submission.Status.GENERATING
        )
        self.evpath.write_text(
            '{"kind":"message","text":"작업 시작"}\n'
            '{"kind":"command","command":"find .","exit_code":0}\n',
            encoding="utf-8",
        )
        url = reverse("submissions:events_json", kwargs={"pk": sub.pk})
        d = self.client.get(url).json()
        self.assertEqual(d["events"][0]["text"], "작업 시작")
        self.assertEqual(d["next"], 2)
        self.assertTrue(d["generating"])
        self.assertFalse(d["done"])
        # incremental fetch: nothing new after the last offset
        d2 = self.client.get(url + "?since=2").json()
        self.assertEqual(d2["events"], [])
        self.assertEqual(d2["next"], 2)

    def test_events_endpoint_empty_before_generation(self):
        sub = Submission.objects.create(participant="p", prompt="x")
        state.to_queued(sub)
        d = self.client.get(
            reverse("submissions:events_json", kwargs={"pk": sub.pk})
        ).json()
        self.assertEqual(d["events"], [])
        self.assertEqual(d["next"], 0)


class RerunAndAdminTests(TestCase):
    def setUp(self):
        self.op = get_user_model().objects.create_user(
            username="op", password="x", is_staff=True
        )

    def test_regular_user_sees_no_operator_controls(self):
        # A non-staff logged-in account can use the site but sees no re-run / admin.
        self.client.force_login(_mk_user("regular", staff=False))
        sub = _make_done_submission()
        body = self.client.get(
            reverse("submissions:result", kwargs={"pk": sub.pk})
        ).content.decode()
        self.assertNotIn("재채점", body)
        self.assertNotIn("· 운영자", body)   # not an operator
        self.assertIn("로그아웃", body)       # but is logged in

    def test_rerun_post_forbidden_for_regular_user(self):
        self.client.force_login(_mk_user("regular", staff=False))
        sub = _make_done_submission()
        resp = self.client.post(reverse("submissions:rerun", kwargs={"pk": sub.pk}))
        self.assertEqual(resp.status_code, 302)  # staff_member_required -> login
        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.DONE)  # untouched

    def test_rerun_button_and_admin_badge_shown_for_staff(self):
        self.client.force_login(self.op)
        sub = _make_done_submission()
        body = self.client.get(
            reverse("submissions:result", kwargs={"pk": sub.pk})
        ).content.decode()
        self.assertIn("재채점", body)
        self.assertIn(reverse("submissions:rerun", kwargs={"pk": sub.pk}), body)
        self.assertIn("· 운영자", body)  # top-right operator indicator

    def test_rerun_post_requires_staff(self):
        sub = _make_done_submission()
        resp = self.client.post(reverse("submissions:rerun", kwargs={"pk": sub.pk}))
        self.assertEqual(resp.status_code, 302)  # redirect to admin login
        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.DONE)  # untouched

    def test_rerun_always_requests_regrade_never_generation(self):
        # Re-grade must NEVER call Codex: the view always sets regrade_only=True,
        # regardless of whether the code dir exists. (The worker fails the row if
        # the code is gone — it does not regenerate.)
        self.client.force_login(self.op)
        for workdir in ("/some/generated/dir", "/nonexistent/dir/xyz"):
            sub = _make_done_submission()
            sub.workdir = workdir
            sub.save(update_fields=["workdir"])
            resp = self.client.post(reverse("submissions:rerun", kwargs={"pk": sub.pk}))
            self.assertRedirects(resp, reverse("submissions:result", kwargs={"pk": sub.pk}))
            sub.refresh_from_db()
            self.assertEqual(sub.status, Submission.Status.QUEUED)
            self.assertTrue(sub.regrade_only)


class PocConsoleTests(TestCase):
    """Operator attack-demonstration console: staff-only, DONE+workdir guarded,
    and the live start/run/stop endpoints (docker layer mocked out)."""

    def setUp(self):
        self.op = get_user_model().objects.create_user(
            username="op", password="x", is_staff=True
        )

    def _done_with_workdir(self):
        sub = Submission.objects.create(participant="tester", prompt="게시판 만들어줘")
        state.to_queued(sub)
        state.to_done(sub, {
            "final_score": 30.0, "grade": "미흡", "pass_fail": "FAIL",
            "findings": [{
                "check_id": "sqli", "category": "dynamic", "label": "SQL 인젝션",
                "owasp": "A03", "score": 0.0, "weight": 10.0,
                "passed": False, "skipped": False, "tool": "",
                "penalty_reasons": ["/login 인증 우회"], "evidence": [],
            }],
        })
        sub.workdir = "/some/generated/dir"
        sub.save(update_fields=["workdir"])
        return sub

    def test_console_requires_staff(self):
        sub = self._done_with_workdir()
        resp = self.client.get(reverse("submissions:poc_console", kwargs={"pk": sub.pk}))
        self.assertEqual(resp.status_code, 302)  # staff_member_required -> login

    def test_console_renders_editable_code_run_button_and_csrf(self):
        self.client.force_login(self.op)
        sub = self._done_with_workdir()
        body = self.client.get(
            reverse("submissions:poc_console", kwargs={"pk": sub.pk})
        ).content.decode()
        self.assertIn('contenteditable="true"', body)   # code is editable
        self.assertIn('id="btn-run"', body)              # run control present
        self.assertIn("csrfmiddlewaretoken", body)       # CSRF token for POSTs
        self.assertIn(reverse("submissions:poc_run", kwargs={"pk": sub.pk}), body)

    def test_start_requires_staff(self):
        sub = self._done_with_workdir()
        resp = self.client.post(reverse("submissions:poc_start", kwargs={"pk": sub.pk}))
        self.assertEqual(resp.status_code, 302)

    def test_start_run_stop_are_json(self):
        self.client.force_login(self.op)
        sub = self._done_with_workdir()
        with mock.patch("submissions.poc_session.start", return_value={"ok": True, "ready": True}) as m_start, \
             mock.patch("submissions.poc_session.run", return_value={"ok": True, "stdout": "EXPLOITED", "stderr": "", "html": "<p>x</p>"}) as m_run, \
             mock.patch("submissions.poc_session.stop", return_value={"ok": True, "stopped": True}) as m_stop:
            r1 = self.client.post(reverse("submissions:poc_start", kwargs={"pk": sub.pk}))
            self.assertEqual(r1.json(), {"ok": True, "ready": True})
            self.assertTrue(m_start.called)
            r2 = self.client.post(
                reverse("submissions:poc_run", kwargs={"pk": sub.pk}),
                data={"check_id": "sqli", "code": "print('x')"},
                content_type="application/json",
            )
            self.assertEqual(r2.json()["stdout"], "EXPLOITED")
            self.assertTrue(m_run.called)
            r3 = self.client.post(reverse("submissions:poc_stop", kwargs={"pk": sub.pk}))
            self.assertTrue(r3.json()["ok"])
            self.assertTrue(m_stop.called)

    def test_run_rejects_empty_payload(self):
        self.client.force_login(self.op)
        sub = self._done_with_workdir()
        resp = self.client.post(
            reverse("submissions:poc_run", kwargs={"pk": sub.pk}),
            data={"check_id": "", "code": ""},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_start_rejected_when_not_done_or_no_workdir(self):
        self.client.force_login(self.op)
        # DONE but no workdir
        sub = _make_done_submission()
        resp = self.client.post(reverse("submissions:poc_start", kwargs={"pk": sub.pk}))
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.json()["ok"])


class PocTemplateTests(TestCase):
    """PoC 소스 카탈로그: 모든 템플릿이 유효 파이썬이고, 재생형(세션 위조) PoC 는
    검증된 쿠키가 있을 때만 탭이 생기고 그 쿠키/경로가 주입되는지."""

    def _finding(self, cid, **kw):
        f = {"check_id": cid, "label": cid, "owasp": "", "score": 0.0,
             "passed": False, "skipped": False, "weight": 5.0}
        f.update(kw)
        return f

    def test_every_template_is_valid_python(self):
        import ast
        from submissions import poc
        for cid in poc._TEMPLATES:
            src = poc.build_poc_source(cid, "http://t:5000")
            src = (src.replace("%%COOKIE_NAME%%", "session")
                      .replace("%%COOKIE_VALUE%%", "eyJ.a.b")
                      .replace("%%ADMIN_PATH%%", "/admin"))
            ast.parse(src)  # raises SyntaxError on a broken template

    def test_simple_exploit_templates_present(self):
        from submissions import poc
        for cid in ("csrf_protection", "debug_true", "idor_profile"):
            self.assertTrue(poc.has_poc(cid))
            terms = poc.poc_terminals([self._finding(cid)], target_url="http://t:5000")
            self.assertEqual([t["check_id"] for t in terms], [cid])
            self.assertIn("http://t:5000", terms[0]["code"])  # TARGET substituted
            self.assertNotIn("%%TARGET%%", terms[0]["code"])

    def test_forgery_replay_injects_verified_cookie(self):
        from submissions import poc
        visible = [self._finding("hardcoded_secret")]
        allf = visible + [{
            "check_id": "session_forgery", "passed": False, "skipped": False, "weight": 0,
            "evidence": ["forged session=eyJ1c2VyX2lkIjoxfQ.aB.cD-eF_gH",
                         "/admin/users -> 200 (admin 콘텐츠 렌더)"],
        }]
        terms = poc.poc_terminals(visible, allf, "http://t:5000")
        self.assertEqual([t["check_id"] for t in terms], ["hardcoded_secret"])
        code = terms[0]["code"]
        self.assertIn("eyJ1c2VyX2lkIjoxfQ.aB.cD-eF_gH", code)
        self.assertIn("/admin/users", code)
        self.assertNotIn("%%", code)  # no leftover placeholders

    def test_forgery_tab_gated_without_verified_cookie(self):
        from submissions import poc
        visible = [self._finding("weak_default_secret"), self._finding("csrf_protection")]
        # no session_forgery finding => no verified cookie => no replay tab
        terms = poc.poc_terminals(visible, visible, "http://t:5000")
        self.assertEqual([t["check_id"] for t in terms], ["csrf_protection"])


class LeaderboardTests(TestCase):
    def _done(self, participant, score, grade="통과", pf="PASS"):
        sub = Submission.objects.create(participant=participant, prompt="x")
        state.to_queued(sub)
        state.to_done(sub, {
            "final_score": score, "grade": grade, "pass_fail": pf,
            "findings": [{
                "check_id": "hardcoded_secret", "label": "하드코딩 시크릿",
                "score": 0.0, "weight": 12.0, "passed": False, "skipped": False,
                "tool": "", "penalty_reasons": ["app.py:23 SECRET_KEY 하드코딩"],
                "evidence": [],
            }],
        })
        return sub

    def test_ranking_is_public_orders_dedupes_excludes_failed(self):
        self._done("alice", 40)
        self._done("bob", 90)
        self._done("alice", 70)  # alice's best is 70
        failed = Submission.objects.create(participant="carol", prompt="x")
        state.to_queued(failed)
        state.to_failed(failed, "boom")
        # Viewable WITHOUT login (public ranking for the booth screen).
        body = self.client.get(reverse("submissions:leaderboard")).content.decode()
        self.assertLess(body.index("bob"), body.index("alice"))
        self.assertEqual(body.count("alice"), 1)
        self.assertIn("70.0", body)
        self.assertNotIn("40.0", body)
        self.assertNotIn("carol", body)

    def test_nickname_links_to_detail(self):
        sub = self._done("dave", 55)
        body = self.client.get(reverse("submissions:leaderboard")).content.decode()
        self.assertIn(reverse("submissions:result", kwargs={"pk": sub.pk}), body)

    def test_leaderboard_does_not_leak_findings(self):
        self._done("alice", 40)
        body = self.client.get(reverse("submissions:leaderboard")).content.decode().lower()
        for term in ["하드코딩", "idor", "app.py", "감점", "secret_key"]:
            self.assertNotIn(term.lower(), body)
