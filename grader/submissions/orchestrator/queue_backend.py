"""Queue backend. The Submission table itself is the queue (Option A); the
factory keeps a seam for another transport, chosen by ``orchestrator.queue_backend``
in config/scoring.yaml."""
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


class DBQueueBackend(QueueBackend):
    """The Submission table IS the queue. The single worker loop is the only
    consumer of the generation stage, so claim needs no locking."""

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


def get_queue_backend(backend_name: str) -> QueueBackend:
    name = (backend_name or "db").lower()
    if name == "db":
        return DBQueueBackend()
    raise ValueError(f"Unknown queue_backend {backend_name!r} (expected 'db').")
