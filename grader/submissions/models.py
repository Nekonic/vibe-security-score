"""Submission model: DB-backed queue row + grading result. Status transitions
go through ``submissions.state`` only."""
from __future__ import annotations

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
    grade = models.CharField(max_length=32, blank=True, default="")
    pass_fail = models.CharField(max_length=16, blank=True, default="")
    findings = models.JSONField(default=list, blank=True)

    generation_retries = models.IntegerField(default=0)
    scoring_retries = models.IntegerField(default=0)

    last_error = models.TextField(blank=True, default="")
    # Generation workdir, tracked so cleanup can remove it.
    workdir = models.CharField(max_length=1024, blank=True, default="")

    queued_at = models.DateTimeField(null=True, blank=True)
    generation_started_at = models.DateTimeField(null=True, blank=True)
    generation_finished_at = models.DateTimeField(null=True, blank=True)
    scoring_started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["submitted_at"]
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
