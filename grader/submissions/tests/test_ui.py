"""Part 1 web UI tests — submit flow, status polling, result screen, and the
security-by-design rule that checks are not disclosed before grading.

Fixtures are fabricated directly (no Codex/Docker): a graded submission is
produced by driving the state machine with a canned report.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import tempfile
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from submissions import state
from submissions.models import Submission


def _make_done_submission() -> Submission:
    sub = Submission.objects.create(participant="tester", prompt="게시판 만들어줘")
    state.to_queued(sub)
    report = {
        "final_score": 62.5,
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

    def test_over_long_prompt_rejected(self):
        # Counted in characters (incl. whitespace); over the cap => 400, nothing queued.
        with mock.patch("submissions.views._max_prompt_chars", return_value=10):
            resp = self.client.post(
                reverse("submissions:submit"), {"prompt": "가" * 50, "nickname": "n"}
            )
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(Submission.objects.count(), 0)
        self.assertIn("자", resp.content.decode())

    def test_korean_prompt_counted_by_char_not_byte(self):
        # 100 Korean chars = 300 UTF-8 bytes but only 100 CHARS — must pass a 200-char cap.
        with mock.patch("submissions.views._max_prompt_chars", return_value=200):
            self.client.post(
                reverse("submissions:submit"), {"prompt": "가" * 100, "nickname": "n"}
            )
        self.assertEqual(Submission.objects.count(), 1)

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
        self.assertEqual(data["final_score"], 62.5)
        self.assertNotIn("grade", data)
        self.assertNotIn("pass_fail", data)

    def test_result_page_renders_findings_and_score(self):
        sub = _make_done_submission()
        body = self.client.get(
            reverse("submissions:result", kwargs={"pk": sub.pk})
        ).content.decode()
        # Score only: no grade line, no PASS/FAIL badge
        self.assertIn("62.5", body)
        self.assertNotIn("등급", body)
        self.assertNotIn(">PASS<", body)
        self.assertNotIn(">FAIL<", body)
        # A failing check with its penalty reason (감점 사유) is shown
        self.assertIn("하드코딩 시크릿", body)
        self.assertIn("app.py:23 SECRET_KEY 하드코딩", body)
        # A passing check shows the ✔ mark
        self.assertIn("기능 게이트", body)
        self.assertIn("✔", body)
        # Skipped aux tool (weight 0) is hidden on the participant result
        self.assertNotIn("gitleaks", body)

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

    def test_failed_generation_shows_no_regrade_button(self):
        # Nothing was generated, so a re-grade could only fail again.
        self.client.force_login(self.op)
        sub = Submission.objects.create(participant="p", prompt="x")
        state.to_failed(sub, "boom")
        body = self.client.get(reverse("submissions:result", kwargs={"pk": sub.pk})).content.decode()
        self.assertNotIn("재채점", body)

    def test_rerun_post_forbidden_for_regular_user(self):
        self.client.force_login(_mk_user("regular", staff=False))
        sub = _make_done_submission()
        resp = self.client.post(reverse("submissions:rerun", kwargs={"pk": sub.pk}))
        self.assertEqual(resp.status_code, 302)  # staff_member_required -> login
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


class KaliConsoleTests(TestCase):
    """Operator Kali console: staff-only, DONE+workdir guarded, JSON start/io/stop
    (docker layer mocked out), and the replay scripts placed in ~/poc."""

    def setUp(self):
        self.op = get_user_model().objects.create_user(
            username="op", password="x", is_staff=True
        )

    def _done_with_workdir(self):
        sub = Submission.objects.create(participant="tester", prompt="게시판 만들어줘")
        state.to_queued(sub)
        state.to_done(sub, {
            "final_score": 30.0,
            "findings": [
                {"check_id": "sqli", "label": "SQL Injection", "score": 0.0, "passed": False, "skipped": False},
                {"check_id": "ssrf", "label": "SSRF", "score": 0.0, "passed": False, "skipped": True},
                {"check_id": "stored_xss", "label": "Stored XSS", "score": 100.0, "passed": True, "skipped": False},
                {"check_id": "security_logging", "label": "보안 로깅", "score": 0.0, "passed": False, "skipped": False},
            ],
        })
        sub.workdir = tempfile.mkdtemp()
        sub.save(update_fields=["workdir"])
        return sub

    def test_start_requires_staff(self):
        sub = self._done_with_workdir()
        resp = self.client.post(reverse("submissions:kali_start", kwargs={"pk": sub.pk}))
        self.assertEqual(resp.status_code, 302)

    def test_start_io_stop_are_json(self):
        self.client.force_login(self.op)
        sub = self._done_with_workdir()
        with mock.patch("submissions.kali_session.start", return_value={"ok": True}) as m_start, \
             mock.patch("submissions.kali_session.io", return_value={"ok": True, "next": 3, "out": "YWJj"}) as m_io, \
             mock.patch("submissions.kali_session.stop", return_value={"ok": True}) as m_stop:
            self.assertEqual(self.client.post(reverse("submissions:kali_start", kwargs={"pk": sub.pk})).json(), {"ok": True})
            r = self.client.post(reverse("submissions:kali_io", kwargs={"pk": sub.pk}),
                                 data={"data": "ls\r", "since": 0}, content_type="application/json")
            self.assertEqual(r.json()["next"], 3)
            self.assertEqual(m_io.call_args.kwargs["data"], "ls\r")
            self.assertTrue(self.client.post(reverse("submissions:kali_stop", kwargs={"pk": sub.pk})).json()["ok"])
            self.assertTrue(m_start.called and m_stop.called)

    def test_start_rejected_without_generated_code(self):
        self.client.force_login(self.op)
        sub = _make_done_submission()
        resp = self.client.post(reverse("submissions:kali_start", kwargs={"pk": sub.pk}))
        self.assertEqual(resp.status_code, 400)

    def test_scripts_only_for_failed_dynamic_checks(self):
        from submissions import kali_session
        sub = self._done_with_workdir()
        sess = kali_session.Session(pk=sub.pk)
        sess.control = mock.Mock(server_address=("0.0.0.0", 4321))
        files = kali_session._poc_files(sub, sess)
        # sqli failed → script; ssrf skipped, stored_xss passed, security_logging static → none.
        self.assertEqual(sorted(k for k in files if k.endswith(".py")), ["sqli.py"])
        info = json.loads(files[".session.json"])
        self.assertEqual(info["expected"]["sqli"], [0.0, False, False])
        self.assertNotIn("security_logging", info["expected"])
        self.assertIn("kali_poc.run('sqli')", files["sqli.py"])


class LeaderboardTests(TestCase):
    def _done(self, participant, score):
        sub = Submission.objects.create(participant=participant, prompt="x")
        state.to_queued(sub)
        state.to_done(sub, {
            "final_score": score,
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

    def test_leaderboard_does_not_leak_findings(self):
        self._done("alice", 40)
        body = self.client.get(reverse("submissions:leaderboard")).content.decode().lower()
        for term in ["하드코딩", "idor", "app.py", "감점", "secret_key"]:
            self.assertNotIn(term.lower(), body)
