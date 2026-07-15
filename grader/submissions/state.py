"""State machine: the ONE place submission ``status`` is mutated. Every
transition stamps timestamps and saves; nothing mutates ``status`` directly."""
from __future__ import annotations

import time
from typing import Any, Mapping, Optional

from django.db import OperationalError
from django.utils import timezone

from .models import Submission

# sqlite (dev/test) serializes writers and can transiently raise "database is
# locked" under bounded-parallel scoring writes; a short bounded retry keeps
# dev/test robust without masking real errors (Postgres needs none of this).
_LOCK_RETRIES = 8
_LOCK_BACKOFF = 0.05


def _save(sub: Submission, *fields: str) -> None:
    """Save only the touched fields plus status."""
    update = set(fields)
    update.add("status")
    _save_with_retry(sub, sorted(update))


def _save_with_retry(sub: Submission, update_fields) -> None:
    for attempt in range(_LOCK_RETRIES):
        try:
            sub.save(update_fields=update_fields)
            return
        except OperationalError as exc:
            if "lock" in str(exc).lower() and attempt + 1 < _LOCK_RETRIES:
                time.sleep(_LOCK_BACKOFF * (attempt + 1))
                continue
            raise


def save_fields(sub: Submission, *fields: str) -> Submission:
    """Persist non-status fields (retry counters, workdir, flags) with the same
    lock-retry as transitions — the one place any Submission write goes through."""
    _save_with_retry(sub, list(fields))
    return sub


def to_queued(sub: Submission) -> Submission:
    sub.status = Submission.Status.QUEUED
    if sub.queued_at is None:
        sub.queued_at = timezone.now()
    _save(sub, "queued_at")
    return sub


def to_generating(sub: Submission) -> Submission:
    sub.status = Submission.Status.GENERATING
    sub.generation_started_at = timezone.now()
    _save(sub, "generation_started_at")
    return sub


def mark_generation_finished(sub: Submission) -> Submission:
    sub.generation_finished_at = timezone.now()
    return save_fields(sub, "generation_finished_at")


def to_scoring(sub: Submission) -> Submission:
    sub.status = Submission.Status.SCORING
    sub.scoring_started_at = timezone.now()
    if sub.generation_finished_at is None:
        sub.generation_finished_at = sub.scoring_started_at
        _save(sub, "scoring_started_at", "generation_finished_at")
    else:
        _save(sub, "scoring_started_at")
    return sub


def to_done(sub: Submission, report: Mapping[str, Any]) -> Submission:
    """Terminal success: copy result fields out of the grading report."""
    sub.status = Submission.Status.DONE
    sub.final_score = report.get("final_score")
    sub.raw_score = report.get("raw_score")
    sub.grade = str(report.get("grade", "") or "")
    # pass_fail may arrive as a string or be derivable from ``passed``.
    pf = report.get("pass_fail")
    if pf is None and "passed" in report:
        pf = "pass" if report.get("passed") else "fail"
    sub.pass_fail = str(pf or "")
    sub.findings = list(report.get("findings", []) or [])
    sub.critical_penalties = list(report.get("critical_penalties", []) or [])
    sub.boot_log = str(report.get("boot_log", "") or "")
    sub.last_error = ""
    sub.finished_at = timezone.now()
    _save(
        sub,
        "final_score",
        "raw_score",
        "grade",
        "pass_fail",
        "findings",
        "critical_penalties",
        "boot_log",
        "last_error",
        "finished_at",
    )
    return sub


def to_failed(sub: Submission, err: Any, *, reason: Optional[str] = None) -> Submission:
    """Terminal failure. ``reason`` overrides the stringified error if given."""
    sub.status = Submission.Status.FAILED
    sub.last_error = reason if reason is not None else str(err)
    sub.finished_at = timezone.now()
    _save(sub, "last_error", "finished_at")
    return sub


def to_rate_limited(sub: Submission, err: Any) -> Submission:
    """Rolling-limit hit. NOT a failure — the pipeline re-queues after backoff."""
    sub.status = Submission.Status.RATE_LIMITED
    sub.last_error = str(err)
    _save(sub, "last_error")
    return sub


def back_to_queued(sub: Submission) -> Submission:
    sub.status = Submission.Status.QUEUED
    _save(sub)
    return sub
