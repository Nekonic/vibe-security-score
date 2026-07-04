"""Queue backend: Option A (DB) default, Option B (Celery) stub. Switching is a
config change (``orchestrator.queue_backend`` in config/scoring.yaml)."""
from __future__ import annotations

from typing import Optional

from ..models import Submission
from .. import state


class QueueBackend:
    """Abstract queue interface. Subclasses implement the transport."""

    def enqueue(self, participant: str, prompt: str) -> Submission:
        raise NotImplementedError

    def claim_next_queued(self) -> Optional[Submission]:
        raise NotImplementedError

    def mark(self, submission: Submission, status: str) -> None:
        raise NotImplementedError


class DBQueueBackend(QueueBackend):
    """Option A: the Submission table IS the queue. The single worker loop is
    the only consumer of the generation stage, so claim needs no locking."""

    def enqueue(self, participant: str, prompt: str) -> Submission:
        sub = Submission.objects.create(participant=participant, prompt=prompt)
        state.to_queued(sub)
        return sub

    def claim_next_queued(self) -> Optional[Submission]:
        return (
            Submission.objects.filter(status=Submission.Status.QUEUED)
            .order_by("submitted_at")
            .first()
        )

    def mark(self, submission: Submission, status: str) -> None:
        # Route through the state machine so timestamps stay consistent.
        mapping = {
            Submission.Status.QUEUED: state.to_queued,
            Submission.Status.GENERATING: state.to_generating,
            Submission.Status.SCORING: state.to_scoring,
        }
        fn = mapping.get(status)
        if fn is None:
            raise ValueError(
                f"mark() only supports simple transitions; got {status!r}. "
                "Use submissions.state directly for done/failed/rate_limited."
            )
        fn(submission)


class CeleryQueueBackend(QueueBackend):
    """Option B stub (Celery+Redis). NOT IMPLEMENTED — kept so switching to
    ``"celery"`` is a config change; no Celery import here."""

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "Option B (Celery+Redis) is a documented stub. Set "
            "orchestrator.queue_backend='db' to use Option A, or implement "
            "CeleryQueueBackend per the docstring routing plan."
        )


def get_queue_backend(backend_name: str) -> QueueBackend:
    name = (backend_name or "db").lower()
    if name == "db":
        return DBQueueBackend()
    if name == "celery":
        return CeleryQueueBackend()  # raises NotImplementedError (stub)
    raise ValueError(f"Unknown queue_backend {backend_name!r} (expected 'db' or 'celery').")
