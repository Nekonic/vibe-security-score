"""Pipeline tests — hermetic, no Docker/Codex (fakes injected).

Maps to the spec's verification points:
  (a) serial generation        -> test_a_serial_generation_no_overlap
  (b) bounded parallel scoring  -> test_b_bounded_parallel_scoring
  (c) fault isolation           -> test_c_fault_isolation
  (d) rate_limited path         -> test_d_rate_limited_then_done
  (e) cleanup                   -> test_e_no_leftover_workdirs
  (f) auth failure              -> test_f_auth_failure_alert_no_retry_storm
"""
from __future__ import annotations

import shutil
import tempfile
import threading
import time
from pathlib import Path

from django.test import TransactionTestCase

from submissions.models import Submission
from submissions.orchestrator import pipeline
from submissions.orchestrator.pipeline import Orchestrator, OrchestratorConfig
from submissions.orchestrator.queue_backend import get_queue_backend

from codex_runner.errors import GenerationError, RateLimitError

from .fakes import (
    CountingGenerate,
    FailForSubmissionGenerate,
    FakeGenerate,
    FakeGrade,
    RaiseOnceThenSucceedGenerate,
)


def _test_config(workdir_base: Path, **overrides) -> OrchestratorConfig:
    """A shrunk, hermetic config: tiny backoff/poll, temp workdir_base."""
    cfg = OrchestratorConfig(
        queue_backend="db",
        generation_concurrency=1,
        scoring_concurrency=2,
        poll_interval_seconds=0.01,
        pipeline_timeout_seconds=30.0,
        workdir_base=str(workdir_base),
        container_name_prefix="vibe-sec-test-",
        generation_max=3,
        scoring_max=2,
        backoff_base_seconds=0.0,  # no real waiting in tests
        backoff_max_seconds=0.0,
        auth_failure_signals=["not logged in", "please run codex login", "unauthorized"],
    )
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


class PipelineTestBase(TransactionTestCase):
    # Scoring runs in pool THREADS with their own DB connections. TestCase wraps
    # each test in a single transaction those threads can't see; TransactionTestCase
    # commits for real so cross-thread reads/writes are visible.
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="grader-test-"))
        self.workdir_base = self.tmp / "submissions"
        self.workdir_base.mkdir(parents=True, exist_ok=True)
        self.backend = get_queue_backend("db")
        pipeline.clear_auth_alert()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)
        pipeline.clear_auth_alert()

    def _drain(self, orch: Orchestrator) -> None:
        """Single-worker drain: serially process every queued submission, then
        wait for all scoring futures. Mirrors run_worker without the sleep loop.
        Re-queued (rate-limited) submissions are picked up again."""
        # Bound the loop so a bug can't hang the suite.
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            sub = self.backend.claim_next_queued()
            if sub is None:
                break
            orch.process_one(sub)
        orch.wait_for_scoring(timeout=20.0)
        orch.shutdown(wait=True)


class RegradeTests(PipelineTestBase):
    def test_regrade_only_skips_generation_and_scores_existing_code(self):
        cfg = _test_config(self.workdir_base)
        gen = FakeGenerate(self.workdir_base, duration=0.02)
        grade = FakeGrade(duration=0.02)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)

        code = self.tmp / "generated_regrade"
        code.mkdir()
        (code / "app.py").write_text("# existing generated app\n", encoding="utf-8")
        sub = Submission.objects.create(
            participant="p", prompt="x",
            status=Submission.Status.QUEUED, regrade_only=True, workdir=str(code),
        )

        self._drain(orch)

        self.assertEqual(len(gen.intervals), 0, "Codex generation must be skipped on re-grade")
        self.assertIn(str(sub.pk), grade.calls, "existing code should be re-scored")
        sub.refresh_from_db()
        self.assertFalse(sub.regrade_only, "flag is consumed after one re-grade")
        self.assertEqual(sub.status, Submission.Status.DONE)

    def test_regrade_without_code_fails_and_never_generates(self):
        # Re-grade must NEVER fall back to Codex: if the code dir is gone, the
        # submission FAILS instead of regenerating.
        cfg = _test_config(self.workdir_base)
        gen = FakeGenerate(self.workdir_base, duration=0.02)
        grade = FakeGrade(duration=0.02)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)

        sub = Submission.objects.create(
            participant="p", prompt="x", status=Submission.Status.QUEUED,
            regrade_only=True, workdir="/gone/data/generated/999",
        )

        self._drain(orch)

        self.assertEqual(len(gen.intervals), 0, "must NOT call Codex on a code-less re-grade")
        self.assertEqual(grade.calls, [], "nothing to score")
        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.FAILED)
        self.assertIn("코드가 없", sub.last_error)


class SerialGenerationTests(PipelineTestBase):
    def test_a_serial_generation_no_overlap(self) -> None:
        """(a) Enqueue 5; assert NO two generation intervals overlap."""
        cfg = _test_config(self.workdir_base, scoring_concurrency=3)
        gen = FakeGenerate(self.workdir_base, duration=0.05)
        grade = FakeGrade(duration=0.02)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        for i in range(5):
            self.backend.enqueue(f"p{i}", f"prompt {i}")
        self._drain(orch)

        self.assertEqual(len(gen.intervals), 5)
        self.assertFalse(gen.any_overlap(), "two generations overlapped — not serial")
        self.assertEqual(
            Submission.objects.filter(status=Submission.Status.DONE).count(), 5
        )


class BoundedScoringTests(PipelineTestBase):
    def test_b_bounded_parallel_scoring(self) -> None:
        """(b) peak scoring concurrency <= scoring_concurrency AND >1 ran at once."""
        cfg = _test_config(self.workdir_base, scoring_concurrency=2)
        # Fast generation so scoring jobs pile up; slow scoring so they overlap.
        gen = FakeGenerate(self.workdir_base, duration=0.0)
        grade = FakeGrade(duration=0.25)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        for i in range(5):
            self.backend.enqueue(f"p{i}", f"prompt {i}")
        self._drain(orch)

        self.assertLessEqual(
            grade.peak_concurrency, cfg.scoring_concurrency,
            f"peak scoring concurrency {grade.peak_concurrency} exceeded cap {cfg.scoring_concurrency}",
        )
        self.assertGreater(
            grade.peak_concurrency, 1,
            "scoring never ran in parallel — expected >1 concurrent with cap 2",
        )
        self.assertEqual(len(grade.calls), 5)


class FaultIsolationTests(PipelineTestBase):
    def test_c_fault_isolation(self) -> None:
        """(c) one submission's generate raises -> it fails; others reach done."""
        cfg = _test_config(self.workdir_base)
        subs = [self.backend.enqueue(f"p{i}", f"prompt {i}") for i in range(4)]
        fail_pk = str(subs[1].pk)
        gen = FailForSubmissionGenerate(
            self.workdir_base, fail_pk, GenerationError("boom"), duration=0.02
        )
        grade = FakeGrade(duration=0.02)
        # generation_max=1 so the failing one fails immediately (no retry storm).
        cfg.generation_max = 1
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        self._drain(orch)

        failed = Submission.objects.get(pk=fail_pk)
        self.assertEqual(failed.status, Submission.Status.FAILED)
        self.assertIn("boom", failed.last_error)

        others = Submission.objects.exclude(pk=fail_pk)
        self.assertEqual(others.count(), 3)
        for o in others:
            self.assertEqual(o.status, Submission.Status.DONE, f"#{o.pk} not done")


class RateLimitedTests(PipelineTestBase):
    def test_d_rate_limited_then_done(self) -> None:
        """(d) generate raises RateLimitError once then succeeds -> passes through
        rate_limited and finally done (not dropped)."""
        cfg = _test_config(self.workdir_base)
        exc = RateLimitError(retry_after=0.0, detail="5-hour limit")
        gen = RaiseOnceThenSucceedGenerate(self.workdir_base, exc, duration=0.01)
        grade = FakeGrade(duration=0.02)

        # Observe that the submission actually entered RATE_LIMITED at some point.
        seen_rate_limited = threading.Event()
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        sub = self.backend.enqueue("solo", "please generate")

        # First pass: hits rate limit, re-queues.
        orch.process_one(sub)
        sub.refresh_from_db()
        # After back_to_queued it's QUEUED again; but last_error records the RL,
        # and generation_retries incremented — evidence it went through RL.
        self.assertEqual(sub.status, Submission.Status.QUEUED)
        self.assertEqual(sub.generation_retries, 1)

        # Second pass: succeeds -> scoring -> done.
        nxt = self.backend.claim_next_queued()
        self.assertIsNotNone(nxt)
        orch.process_one(nxt)
        orch.wait_for_scoring(timeout=10.0)
        orch.shutdown(wait=True)

        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.DONE)
        self.assertEqual(sub.final_score, 72.5)


class CleanupTests(PipelineTestBase):
    def test_e_no_leftover_workdirs(self) -> None:
        """(e) after processing, no leftover per-submission workdirs remain."""
        cfg = _test_config(self.workdir_base)
        gen = FakeGenerate(self.workdir_base, duration=0.01)
        grade = FakeGrade(duration=0.02)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        for i in range(3):
            self.backend.enqueue(f"p{i}", f"prompt {i}")
        self._drain(orch)

        leftovers = [p for p in self.workdir_base.iterdir() if p.is_dir()]
        self.assertEqual(
            leftovers, [], f"leftover workdirs after processing: {leftovers}"
        )


class AuthFailureTests(PipelineTestBase):
    def test_f_auth_failure_alert_no_retry_storm(self) -> None:
        """(f) generate error containing an auth signal -> failed with auth reason
        + alert set, and it did NOT retry generation_max times."""
        cfg = _test_config(self.workdir_base, generation_max=3)
        exc = GenerationError("codex failed", detail="Please run codex login (not logged in)")
        gen = CountingGenerate(self.workdir_base, exc)
        grade = FakeGrade(duration=0.01)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        sub = self.backend.enqueue("solo", "generate please")
        orch.process_one(sub)
        orch.shutdown(wait=True)

        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.FAILED)
        self.assertIn("Codex 인증 만료", sub.last_error)
        self.assertTrue(pipeline.auth_alert_active(), "operator alert flag not set")
        # Auth failure must short-circuit — exactly ONE generate call, not
        # generation_max attempts.
        self.assertEqual(gen.count, 1, "auth failure burned per-submission retries")
        # And it must not have re-queued.
        self.assertEqual(
            Submission.objects.filter(status=Submission.Status.QUEUED).count(), 0
        )


class QueuePositionTests(PipelineTestBase):
    def test_queue_position_helper(self) -> None:
        a = self.backend.enqueue("a", "p")
        b = self.backend.enqueue("b", "p")
        c = self.backend.enqueue("c", "p")
        self.assertEqual(a.queue_position(), 1)
        self.assertEqual(b.queue_position(), 2)
        self.assertEqual(c.queue_position(), 3)
        # Once a is no longer queued, positions shift and a returns 0.
        from submissions import state
        state.to_generating(a)
        self.assertEqual(a.queue_position(), 0)
        b.refresh_from_db()
        self.assertEqual(b.queue_position(), 1)
