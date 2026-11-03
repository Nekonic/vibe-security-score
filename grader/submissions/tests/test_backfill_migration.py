"""0012: participant_prompt backfill for rows submitted before 0010."""
from __future__ import annotations

import importlib

from django.apps import apps
from django.test import TestCase

from submissions.models import Submission

mig = importlib.import_module("submissions.migrations.0012_backfill_participant_prompt")

# An older system prompt (not today's file) — only its closing paragraph is shared.
_OLD_SYSTEM = "예전 시스템 프롬프트.\n\n- 규칙 하나\n\n" + mig._ANCHOR + "\n"
_LONG = "OWASP 기준으로 구현하라.\r\n- 서버 측 인가\r\n\r\n- 보안 헤더\n" + "가" * 500


def _legacy(prompt, *, score=80.72):
    sub = Submission.objects.create(participant="p", prompt=prompt)
    Submission.objects.filter(pk=sub.pk).update(
        status=Submission.Status.DONE, participant_prompt="", prompt_chars=0,
        efficiency=1.0, security_score=score, final_score=score)
    return sub.pk


class BackfillTests(TestCase):
    def test_recovers_from_an_old_system_prompt(self):
        built = f"{_OLD_SYSTEM.rstrip()}\n\n{_LONG.strip()}\n"
        self.assertEqual(mig.recover_participant_prompt(built), _LONG.strip())

    def test_unrecoverable_is_none(self):
        self.assertIsNone(mig.recover_participant_prompt("게시판 만들어줘"))
        self.assertIsNone(mig.recover_participant_prompt(_OLD_SYSTEM.rstrip() + "\n\n"))

    def test_backfill_rescores_long_prompt_and_leaves_others(self):
        long_pk = _legacy(f"{_OLD_SYSTEM.rstrip()}\n\n{_LONG.strip()}\n")
        short_pk = _legacy(f"{_OLD_SYSTEM.rstrip()}\n\n.\n", score=65.95)
        odd_pk = _legacy("게시판 만들어줘", score=50.0)
        mig.backfill(apps, None)

        sub = Submission.objects.get(pk=long_pk)
        n = len(_LONG.strip())
        self.assertEqual(sub.participant_prompt, _LONG.strip())
        self.assertEqual(sub.prompt_chars, n)
        m = 1.0 - 0.2 * (n - 200) / 800
        self.assertAlmostEqual(sub.efficiency, round(m, 4))
        self.assertEqual(sub.final_score, round(80.72 * round(m, 4), 2))
        self.assertEqual(sub.security_score, 80.72)

        sub = Submission.objects.get(pk=short_pk)
        self.assertEqual((sub.participant_prompt, sub.prompt_chars, sub.efficiency, sub.final_score),
                         (".", 1, 1.0, 65.95))

        sub = Submission.objects.get(pk=odd_pk)
        self.assertEqual((sub.participant_prompt, sub.prompt_chars, sub.final_score), ("", 0, 50.0))
