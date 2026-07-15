"""Single worker: bounded-parallel generation -> bounded-parallel scoring."""
from __future__ import annotations

import shutil
import signal
import subprocess
import time
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import close_old_connections

from submissions import state
from submissions.models import Submission
from submissions.orchestrator.pipeline import Orchestrator, OrchestratorConfig
from submissions.orchestrator.queue_backend import get_queue_backend


def _recover_orphans() -> int:
    """A killed/crashed worker leaves rows stuck in GENERATING/SCORING. At startup
    NOTHING is in flight, so those are orphans. Fail them (don't auto-regenerate —
    that could silently re-burn Codex quota); the operator re-submits or re-grades
    deliberately. Returns how many were recovered."""
    orphans = Submission.objects.filter(
        status__in=(Submission.Status.GENERATING, Submission.Status.SCORING)
    )
    n = 0
    for sub in orphans:
        state.to_failed(sub, "워커 중단으로 중단된 작업 — 재제출/재채점 필요")
        n += 1
    return n


def _startup_sweep(config: OrchestratorConfig) -> None:
    """Reclaim leftovers from a previous crashed run. Safe: nothing is in flight
    yet at startup, so every workdir/container with our prefix is an orphan."""
    base = Path(config.workdir_base)
    if base.exists():
        for child in base.iterdir():
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
    try:
        ids = subprocess.run(
            ["docker", "ps", "-aq", "--filter", f"name={config.container_name_prefix}"],
            capture_output=True, text=True, timeout=30, check=False,
        ).stdout.split()
        if ids:
            subprocess.run(["docker", "rm", "-f", *ids],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=60, check=False)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        pass


class Command(BaseCommand):
    help = "Run the submission worker (parallel generation + parallel scoring)."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--once", action="store_true",
                            help="Drain the queue once and exit.")
        parser.add_argument("--max-iterations", type=int, default=0,
                            help="Stop after N poll iterations (0 = unbounded).")

    def handle(self, *args, **options) -> None:
        config = OrchestratorConfig.from_scoring_config()
        backend = get_queue_backend(config.queue_backend)
        orch = Orchestrator(config)
        self._stop = False

        def _graceful(_signum, _frame):
            self._stop = True

        signal.signal(signal.SIGINT, _graceful)
        signal.signal(signal.SIGTERM, _graceful)

        _startup_sweep(config)
        recovered = _recover_orphans()
        if recovered:
            self.stdout.write(self.style.WARNING(
                f"고아 작업 {recovered}건 정리(실패 처리) — 이전 워커 중단 흔적"))
        self.stdout.write(self.style.SUCCESS(
            f"Worker started: generation_concurrency={config.generation_concurrency}, "
            f"scoring_concurrency={config.scoring_concurrency}"))

        # Generation runs in a bounded pool (size = generation_concurrency). The
        # loop dispatches up to the admin-tunable ``codex_max_sessions`` at once
        # (clamped to the pool size), re-read each iteration so operators can throttle
        # live. ``inflight`` (pk -> Future) both bounds dispatch and, via exclude_ids,
        # stops re-claiming a row before its pool thread has moved it out of QUEUED.
        from submissions.models import GraderSettings

        inflight: dict = {}
        iterations = 0
        try:
            while not self._stop:
                for pk in [pk for pk, fut in inflight.items() if fut.done()]:
                    inflight.pop(pk)

                limit = min(
                    config.generation_concurrency,
                    max(1, GraderSettings.load().codex_max_sessions),
                )
                claimed = False
                if len(inflight) < limit:
                    sub = backend.claim_next_queued(exclude_ids=inflight.keys())
                    if sub is not None:
                        self.stdout.write(f"→ #{sub.pk} ({sub.participant})")
                        inflight[sub.pk] = orch.submit_generation(sub)
                        claimed = True
                close_old_connections()

                if not claimed:
                    if options["once"] and not inflight:
                        break
                    time.sleep(config.poll_interval_seconds)

                iterations += 1
                if options["max_iterations"] and iterations >= options["max_iterations"]:
                    break
        finally:
            orch.shutdown(wait=True)
            self.stdout.write(self.style.SUCCESS("Worker stopped."))
