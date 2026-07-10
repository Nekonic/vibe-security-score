"""The grading pipeline: queued -> generating -> scoring -> done (or failed).

Generation is globally serial (one worker loop under a module-global lock,
because of the shared ChatGPT rolling limit); scoring is bounded-parallel in a
thread pool. Per-submission processing is fault-isolated and cleans up its
workdir/container in ``finally``. ``generate_fn``/``grade_fn`` are injectable
(tests use fakes; defaults are the real codex_runner/scoring)."""
from __future__ import annotations

import logging
import shutil
import subprocess
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, List, Optional

from django.db import close_old_connections

from ..models import Submission
from .. import state

logger = logging.getLogger("submissions.orchestrator")

# Enforces generation-concurrency == 1 (the single worker loop is the primary
# guarantee; this is belt-and-suspenders).
_GENERATION_LOCK = threading.Lock()

# Operator alert flag for Codex auth expiry; run_worker/tests can inspect it.
_AUTH_ALERT = threading.Event()


def auth_alert_active() -> bool:
    return _AUTH_ALERT.is_set()


def clear_auth_alert() -> None:
    _AUTH_ALERT.clear()


# Lazy defaults so importing this module needs no Docker/Codex.
def _default_generate_fn() -> Callable[..., Path]:
    from codex_runner import generate

    return generate


def _default_grade_fn() -> Callable[..., dict]:
    from scoring import grade_submission

    return grade_submission


@dataclass
class OrchestratorConfig:
    """Typed view over config/scoring.yaml ``orchestrator:``."""
    keep_generated: bool = False
    queue_backend: str = "db"
    generation_concurrency: int = 1
    scoring_concurrency: int = 2
    poll_interval_seconds: float = 2.0
    pipeline_timeout_seconds: float = 900.0
    workdir_base: str = "data/submissions"
    container_name_prefix: str = "vibe-sec-dyn-"
    generation_max: int = 3
    scoring_max: int = 2
    backoff_base_seconds: float = 30.0
    backoff_max_seconds: float = 3600.0
    auth_failure_signals: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.auth_failure_signals is None:
            self.auth_failure_signals = []

    @classmethod
    def from_scoring_config(cls, config: Any = None) -> "OrchestratorConfig":
        if config is None:
            from scoring.config import load_config

            config = load_config()
        g = config.get  # dotted getter
        return cls(
            keep_generated=bool(g("orchestrator.keep_generated", False)),
            queue_backend=g("orchestrator.queue_backend", "db"),
            generation_concurrency=int(g("orchestrator.generation_concurrency", 1)),
            scoring_concurrency=int(g("orchestrator.scoring_concurrency", 2)),
            poll_interval_seconds=float(g("orchestrator.poll_interval_seconds", 2)),
            pipeline_timeout_seconds=float(g("orchestrator.pipeline_timeout_seconds", 900)),
            workdir_base=str(g("orchestrator.workdir_base", "data/submissions")),
            container_name_prefix=str(g("orchestrator.container_name_prefix", "vibe-sec-dyn-")),
            generation_max=int(g("orchestrator.retry.generation_max", 3)),
            scoring_max=int(g("orchestrator.retry.scoring_max", 2)),
            backoff_base_seconds=float(g("orchestrator.retry.backoff_base_seconds", 30)),
            backoff_max_seconds=float(g("orchestrator.retry.backoff_max_seconds", 3600)),
            auth_failure_signals=list(g("orchestrator.auth_failure.signals", []) or []),
        )

    def backoff(self, attempt: int) -> float:
        """Exponential backoff: base * 2**attempt, capped at backoff_max."""
        raw = self.backoff_base_seconds * (2 ** attempt)
        return min(raw, self.backoff_max_seconds)


class Orchestrator:
    """Drives submissions through the pipeline with the concurrency policy."""

    def __init__(
        self,
        config: OrchestratorConfig,
        *,
        generate_fn: Optional[Callable[..., Path]] = None,
        grade_fn: Optional[Callable[..., dict]] = None,
        scoring_config: Any = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self.config = config
        self._generate_fn = generate_fn or _default_generate_fn()
        self._grade_fn = grade_fn or _default_grade_fn()
        self._scoring_config = scoring_config
        self._sleep = sleep_fn
        self._scoring_pool = ThreadPoolExecutor(
            max_workers=max(1, config.scoring_concurrency),
            thread_name_prefix="scoring",
        )
        self._scoring_futures: List[Future] = []

    def track_future(self, fut: Future) -> None:
        self._scoring_futures.append(fut)

    def wait_for_scoring(self, timeout: Optional[float] = None) -> None:
        for fut in list(self._scoring_futures):
            fut.result(timeout=timeout)

    def shutdown(self, wait: bool = True) -> None:
        self._scoring_pool.shutdown(wait=wait)

    def _is_auth_failure(self, err: BaseException) -> bool:
        text = f"{err} {getattr(err, 'detail', '') or ''}".lower()
        return any(sig.lower() in text for sig in (self.config.auth_failure_signals or []))

    def _cleanup(self, sub: Submission, workdir: Optional[Path]) -> None:
        """Remove the workdir + any leftover container (best-effort; never raises)."""
        if not self.config.keep_generated:
            try:
                if workdir and Path(workdir).exists():
                    shutil.rmtree(workdir, ignore_errors=True)
            except Exception:  # pragma: no cover - defensive
                logger.warning("workdir cleanup failed for #%s", sub.pk, exc_info=True)
            container = f"{self.config.container_name_prefix}{sub.pk}"
            try:
                subprocess.run(
                    ["docker", "rm", "-f", container],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
            except (FileNotFoundError, subprocess.SubprocessError, OSError):
                # Docker not installed / not running in this env — fine.
                pass

    def process_generation(self, sub: Submission) -> Optional[Path]:
        """Serial generation (under the global lock). Returns the workdir Path,
        or None if re-queued (rate limit) / failed — caller skips scoring."""
        with _GENERATION_LOCK:
            attempt = sub.generation_retries
            state.to_generating(sub)
            # Live activity sink: redacted codex events streamed to events.jsonl so
            # the participant can watch generation in real time (read-only).
            try:
                from codex_runner.activity import open_sink
                event_sink, _ = open_sink(self._scoring_config, str(sub.pk))
            except Exception:  # never let the live view break generation
                event_sink = None
            try:
                workdir = self._generate_fn(
                    str(sub.pk), sub.prompt, config=self._scoring_config,
                    event_sink=event_sink,
                )
            except Exception as err:  # noqa: BLE001 - classify below
                return self._handle_generation_error(sub, err, attempt)

            sub.workdir = str(workdir)
            sub.save(update_fields=["workdir"])
            state.mark_generation_finished(sub)
            return Path(workdir)

    def _handle_generation_error(
        self, sub: Submission, err: Exception, attempt: int
    ) -> None:
        from codex_runner.errors import (
            GenerationError,
            GenerationTimeoutError,
            RateLimitError,
        )

        # (a) GLOBAL Codex-auth failure — do NOT burn per-submission retries.
        if self._is_auth_failure(err):
            reason = "Codex 인증 만료 — 운영자 확인 필요"
            logger.error(
                "OPERATOR ALERT: %s (submission #%s): %s",
                reason,
                sub.pk,
                getattr(err, "detail", "") or err,
            )
            _AUTH_ALERT.set()
            state.to_failed(sub, err, reason=reason)
            return None

        # (b) Rate limit — NOT a failure. Hold, backoff, re-queue.
        if isinstance(err, RateLimitError):
            state.to_rate_limited(sub, err)
            retry_after = getattr(err, "retry_after", None)
            wait = float(retry_after) if retry_after is not None else self.config.backoff(attempt)
            sub.generation_retries = attempt + 1
            sub.save(update_fields=["generation_retries"])
            logger.info(
                "submission #%s rate-limited; re-queue after %.1fs", sub.pk, wait
            )
            self._sleep(wait)
            state.back_to_queued(sub)
            return None

        # (c) Timeout / generic generation error — retry up to generation_max.
        if isinstance(err, (GenerationTimeoutError, GenerationError)):
            if attempt + 1 < self.config.generation_max:
                sub.generation_retries = attempt + 1
                sub.save(update_fields=["generation_retries"])
                wait = self.config.backoff(attempt)
                logger.info(
                    "submission #%s generation error (attempt %d/%d); retry after %.1fs: %s",
                    sub.pk, attempt + 1, self.config.generation_max, wait, err,
                )
                self._sleep(wait)
                state.back_to_queued(sub)
                return None
            logger.warning("submission #%s generation failed permanently: %s", sub.pk, err)
            state.to_failed(sub, err)
            return None

        # (d) Anything else — treat as a hard generation failure (fault-isolated).
        logger.warning("submission #%s unexpected generation error: %s", sub.pk, err)
        state.to_failed(sub, err)
        return None

    def process_scoring(self, sub: Submission, workdir: Path) -> None:
        """Run scoring in a pool thread; retry infra errors up to scoring_max,
        then to_failed. Always cleans up the workdir in ``finally``."""
        try:
            state.to_scoring(sub)
            attempt = 0
            while True:
                try:
                    report = self._grade_fn(
                        str(sub.pk), str(workdir), self._scoring_config
                    )
                except Exception as err:  # noqa: BLE001 - infra/container error
                    if attempt + 1 < self.config.scoring_max:
                        attempt += 1
                        sub.scoring_retries = attempt
                        state._save_with_retry(sub, ["scoring_retries"])
                        wait = self.config.backoff(attempt - 1)
                        logger.info(
                            "submission #%s scoring error (attempt %d/%d); retry after %.1fs: %s",
                            sub.pk, attempt, self.config.scoring_max, wait, err,
                        )
                        self._sleep(wait)
                        continue
                    logger.warning("submission #%s scoring failed permanently: %s", sub.pk, err)
                    state.to_failed(sub, err)
                    return
                # success
                state.to_done(sub, report)
                return
        finally:
            self._cleanup(sub, workdir)
            close_old_connections()  # this ran in a pool thread

    def submit_scoring(self, sub: Submission, workdir: Path) -> Future:
        fut = self._scoring_pool.submit(self._scoring_job, sub, workdir)
        self.track_future(fut)
        return fut

    def _scoring_job(self, sub: Submission, workdir: Path) -> None:
        started = time.monotonic()
        try:
            self.process_scoring(sub, workdir)
        except Exception as err:  # noqa: BLE001 - never let a pool thread die silently
            logger.error("submission #%s scoring crashed: %s", sub.pk, err, exc_info=True)
            try:
                state.to_failed(sub, err)
            except Exception:  # pragma: no cover
                pass
            self._cleanup(sub, workdir)
        finally:
            elapsed = time.monotonic() - started
            if elapsed > self.config.pipeline_timeout_seconds:
                logger.warning(
                    "submission #%s exceeded pipeline_timeout during scoring (%.1fs)",
                    sub.pk, elapsed,
                )

    def process_one(self, sub: Submission) -> Optional[Future]:
        """Serial generation then queued scoring for one submission. Returns the
        scoring Future or None. Fault-isolated: any error fails only this one."""
        try:
            # Operator re-grade: score the existing generated code, NEVER Codex.
            if sub.regrade_only:
                sub.regrade_only = False
                sub.save(update_fields=["regrade_only"])
                wd = Path(sub.workdir) if sub.workdir else None
                if wd is not None and wd.is_dir():
                    # Leave QUEUED synchronously so the poll loop won't re-claim it.
                    state.to_scoring(sub)
                    return self.submit_scoring(sub, wd)
                # Code is gone: FAIL — a re-grade must never fall back to Codex.
                state.to_failed(sub, "재채점할 생성 코드가 없습니다")
                return None
            workdir = self.process_generation(sub)
            if workdir is None:
                # re-queued (rate limit / retry) or already failed — nothing more.
                return None
            return self.submit_scoring(sub, workdir)
        except Exception as err:  # noqa: BLE001 - fault isolation for the queue
            logger.error("submission #%s pipeline crashed: %s", sub.pk, err, exc_info=True)
            try:
                state.to_failed(sub, err)
            except Exception:  # pragma: no cover
                pass
            # Best-effort cleanup if we captured a workdir on the row.
            wd = Path(sub.workdir) if sub.workdir else None
            self._cleanup(sub, wd)
            return None
