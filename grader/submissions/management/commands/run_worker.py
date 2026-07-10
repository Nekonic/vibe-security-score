"""Single worker: serial generation -> bounded-parallel scoring (Option A)."""
from __future__ import annotations

import shutil
import signal
import subprocess
import time
from pathlib import Path

from django.core.management.base import BaseCommand
from django.db import close_old_connections

from submissions.orchestrator.pipeline import Orchestrator, OrchestratorConfig
from submissions.orchestrator.queue_backend import get_queue_backend


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
    help = "Run the submission worker (serial generation + parallel scoring)."

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
        self.stdout.write(self.style.SUCCESS(
            f"Worker started: scoring_concurrency={config.scoring_concurrency}"))

        iterations = 0
        try:
            while not self._stop:
                sub = backend.claim_next_queued()
                if sub is None:
                    if options["once"]:
                        break
                    time.sleep(config.poll_interval_seconds)
                else:
                    self.stdout.write(f"→ #{sub.pk} ({sub.participant})")
                    orch.process_one(sub)
                    close_old_connections()
                iterations += 1
                if options["max_iterations"] and iterations >= options["max_iterations"]:
                    break
        finally:
            orch.shutdown(wait=True)
            self.stdout.write(self.style.SUCCESS("Worker stopped."))
