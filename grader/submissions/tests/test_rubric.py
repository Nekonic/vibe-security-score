"""Result-page breakdown: category points must add up to the raw score, each failed
check shows the real points it lost, and weight-0 categories stay out of the score."""
from django.test import TestCase

from submissions import rubric
from submissions.models import Submission


def _f(cid, cat, score, weight, share, passed=None):
    return {"check_id": cid, "category": cat, "label": cid, "score": score, "weight": weight,
            "passed": score >= 100 if passed is None else passed, "skipped": False,
            "category_weight": share, "penalty_reasons": []}


class BreakdownTests(TestCase):
    def test_points_sum_to_raw_and_reference_is_separate(self):
        sub = Submission.objects.create(participant="t", prompt="p", findings=[
            _f("idor_profile", "access_control", 100, 7.5, 0.6),
            _f("access_control_admin", "access_control", 0, 8, 0.6),
            _f("csrf_protection", "secure_coding", 50, 5, 0.4),
            _f("functional", "functional", 100, 10, 0.0),
        ], critical_penalties=[{"check_id": "access_control_admin", "penalty": 15}])
        b = rubric.breakdown(sub)
        ac, sc = b["domains"]
        self.assertEqual((ac["max_points"], sc["max_points"]), (60.0, 40.0))
        # access_control_admin owns 8/15.5 of 60 points and scored 0.
        self.assertEqual(ac["failed"][0]["lost"], round(60 * 8 / 15.5, 1))
        self.assertEqual(ac["failed"][0]["critical"], 15)
        self.assertEqual(sc["failed"][0]["lost"], 20.0)
        raw = 60 * 7.5 / 15.5 + 40 * 0.5
        self.assertAlmostEqual(ac["earned"] + sc["earned"], raw, delta=0.1)
        self.assertEqual([f["check_id"] for f in b["reference"]], ["functional"])
