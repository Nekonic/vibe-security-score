"""Live-activity API: only an operator re-grade reports ``regrade`` — a new
submission that is still queued or rate-limited must not read as one."""
from django.test import TestCase
from django.urls import reverse

from submissions.models import Submission


class RegradeFlagTests(TestCase):
    def _events(self, **fields):
        sub = Submission.objects.create(participant="t", prompt="p", participant_prompt="p", **fields)
        return self.client.get(reverse("submissions:events_json", kwargs={"pk": sub.pk})).json()

    def test_new_submission_waiting_is_not_a_regrade(self):
        for status in (Submission.Status.QUEUED, Submission.Status.RATE_LIMITED,
                       Submission.Status.GENERATING):
            self.assertFalse(self._events(status=status)["regrade"], status)

    def test_regrade_is_flagged_while_queued_and_scoring(self):
        for status in (Submission.Status.QUEUED, Submission.Status.SCORING):
            d = self._events(status=status, regrade_only=True)
            self.assertTrue(d["regrade"], status)
            self.assertEqual(d["events"], [])  # never replays the original generation
