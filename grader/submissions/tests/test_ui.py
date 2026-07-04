"""Part 1 web UI tests — submit flow, status polling, result screen, and the
security-by-design rule that checks are not disclosed before grading.

Fixtures are fabricated directly (no Codex/Docker): a graded submission is
produced by driving the state machine with a canned report.
"""
from __future__ import annotations

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


class SubmitPageTests(TestCase):
    def test_get_prefills_prompt_from_config_file(self):
        resp = self.client.get(reverse("submissions:submit"))
        self.assertEqual(resp.status_code, 200)
        body = resp.content.decode()
        # The textarea is prefilled with the config default prompt.
        self.assertIn("<textarea", body)
        # A distinctive line from config/default_prompt.txt must be present.
        self.assertIn("게시판", _default_prompt())
        self.assertIn(_default_prompt().strip().splitlines()[0], body)

    def test_submit_creates_queued_submission(self):
        resp = self.client.post(
            reverse("submissions:submit"),
            {"prompt": "나만의 프롬프트", "nickname": "alice"},
        )
        sub = Submission.objects.get()
        self.assertEqual(sub.prompt, "나만의 프롬프트")
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

    def test_ranking_orders_by_score_dedupes_participant_excludes_failed(self):
        self._done("alice", 40)
        self._done("bob", 90)
        self._done("alice", 70)  # alice's best is 70
        failed = Submission.objects.create(participant="carol", prompt="x")
        state.to_queued(failed)
        state.to_failed(failed, "boom")

        body = self.client.get(reverse("submissions:leaderboard")).content.decode()
        # bob (90) ranks above alice (70)
        self.assertLess(body.index("bob"), body.index("alice"))
        # alice appears once (deduped to her best), showing 70.0 not 40.0
        self.assertEqual(body.count("alice"), 1)
        self.assertIn("70.0", body)
        self.assertNotIn("40.0", body)
        # failed submission is excluded
        self.assertNotIn("carol", body)

    def test_leaderboard_does_not_leak_findings(self):
        self._done("alice", 40)
        body = self.client.get(reverse("submissions:leaderboard")).content.decode().lower()
        for term in ["하드코딩", "idor", "app.py", "감점", "secret_key"]:
            self.assertNotIn(term.lower(), body)
