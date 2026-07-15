"""Submission model: DB-backed queue row + grading result. Status transitions
go through ``submissions.state`` only."""
from __future__ import annotations

import time

from django.db import models


class Submission(models.Model):
    class Status(models.TextChoices):
        QUEUED = "queued", "대기 중"
        GENERATING = "generating", "코드 생성 중"
        SCORING = "scoring", "채점 중"
        DONE = "done", "완료"
        FAILED = "failed", "실패"
        RATE_LIMITED = "rate_limited", "생성 제한 대기"

    participant = models.CharField(
        max_length=120,
        help_text="세션 ID 또는 닉네임 (session/nickname).",
    )
    prompt = models.TextField(help_text="참가자가 제출한 프롬프트.")
    submitted_at = models.DateTimeField(auto_now_add=True, db_index=True)

    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
        db_index=True,
    )

    final_score = models.FloatField(null=True, blank=True)
    # Weighted category score BEFORE critical penalties (transparency).
    raw_score = models.FloatField(null=True, blank=True)
    grade = models.CharField(max_length=32, blank=True, default="")
    pass_fail = models.CharField(max_length=16, blank=True, default="")
    findings = models.JSONField(default=list, blank=True)
    # App-wide-exploitable defects deducted from the final score, each with a
    # severity + reproduction + live evidence (shown to justify the deduction).
    critical_penalties = models.JSONField(default=list, blank=True)

    generation_retries = models.IntegerField(default=0)
    scoring_retries = models.IntegerField(default=0)
    # Operator re-run: score the EXISTING generated code again (skip Codex) — e.g.
    # after a scoring-config change. Set by the admin re-run button; the worker
    # consumes it, skipping generation when the generated dir still exists.
    regrade_only = models.BooleanField(default=False)

    last_error = models.TextField(blank=True, default="")
    # Sandbox container log tail when the app failed to boot (shown on the result
    # page so the participant sees WHY dynamic checks couldn't run).
    boot_log = models.TextField(blank=True, default="")
    # Generation workdir, tracked so cleanup can remove it.
    workdir = models.CharField(max_length=1024, blank=True, default="")

    queued_at = models.DateTimeField(null=True, blank=True)
    generation_started_at = models.DateTimeField(null=True, blank=True)
    generation_finished_at = models.DateTimeField(null=True, blank=True)
    scoring_started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["submitted_at"]
        verbose_name = "제출"
        verbose_name_plural = "제출"
        indexes = [
            models.Index(fields=["status", "submitted_at"]),
        ]

    def __str__(self) -> str:  # pragma: no cover
        return f"Submission #{self.pk} [{self.participant}] {self.status}"

    @property
    def is_terminal(self) -> bool:
        return self.status in (self.Status.DONE, self.Status.FAILED)

    def queue_position(self) -> int:
        """1-based position among still-queued submissions; 0 if not queued."""
        if self.status != self.Status.QUEUED:
            return 0
        earlier = Submission.objects.filter(
            status=self.Status.QUEUED,
            submitted_at__lt=self.submitted_at,
        ).count()
        return earlier + 1


class GraderSettings(models.Model):
    """Operator-tunable runtime settings, edited in the admin. Single row (id=1)."""

    codex_model = models.CharField(
        max_length=120,
        blank=True,
        default="",
        help_text="Codex 모델 ID. 비우면 config/scoring.yaml 값(또는 ChatGPT 계정 기본 모델)을 사용.",
    )
    codex_reasoning_effort = models.CharField(
        max_length=32,
        blank=True,
        default="",
        help_text="Codex 추론 강도. 비우면 모델 기본값(default_reasoning_level)을 사용.",
    )
    codex_max_sessions = models.PositiveIntegerField(
        default=5,
        help_text="동시에 실행할 최대 Codex 생성 세션 수 (병렬 생성 상한). "
                  "config의 orchestrator.generation_concurrency(풀 크기)까지만 유효.",
    )

    class Meta:
        verbose_name = "채점기 설정"
        verbose_name_plural = "채점기 설정"

    def __str__(self) -> str:  # pragma: no cover
        return "채점기 설정"

    def save(self, *args, **kwargs) -> None:
        self.pk = 1  # enforce singleton
        super().save(*args, **kwargs)

    @classmethod
    def load(cls) -> "GraderSettings":
        # Read-first (the row is seeded by migration): generation reads this per
        # run, so avoid a write on the hot path (sqlite serializes writers). If the
        # row is missing, create it with a short lock-retry — parallel generation
        # can hit "database is locked" on sqlite (dev/test); Postgres needs none.
        obj = cls.objects.filter(pk=1).first()
        if obj is not None:
            return obj
        from django.db import OperationalError

        for attempt in range(8):
            try:
                obj, _ = cls.objects.get_or_create(pk=1)
                return obj
            except OperationalError as exc:
                if "lock" in str(exc).lower() and attempt < 7:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                raise
        return cls.objects.get(pk=1)
