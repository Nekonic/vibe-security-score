"""Pipeline tests — hermetic, no Docker/Codex (fakes injected).

Maps to the spec's verification points:
  (a) bounded parallel generation -> test_a_bounded_parallel_generation
  (b) bounded parallel scoring  -> test_b_bounded_parallel_scoring
  (c) fault isolation           -> test_c_fault_isolation
  (d) rate_limited path         -> test_d_rate_limited_then_done
  (e) cleanup                   -> test_e_no_leftover_workdirs
  (f) auth failure              -> test_f_auth_failure_alert_no_retry_storm
"""
from __future__ import annotations

import shutil
import tempfile
import time
from pathlib import Path

from unittest import mock

from django.core.management import call_command
from django.test import TransactionTestCase

from submissions.models import GraderSettings, Submission
from submissions.orchestrator import pipeline
from submissions.orchestrator.pipeline import Orchestrator, OrchestratorConfig
from submissions.orchestrator.queue_backend import get_queue_backend

from codex_runner.errors import ContractFailedError, GenerationError, RateLimitError

from .fakes import (
    CountingGenerate,
    FailForSubmissionGenerate,
    FakeGenerate,
    FakeGrade,
    RaiseOnceThenSucceedGenerate,
    RaiseSequenceThenSucceedGenerate,
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
        # Seed the singleton settings row (migration seeds it in real runs, but
        # TransactionTestCase flushes between tests) so per-generation load() reads
        # instead of racing a create under parallel generation.
        from submissions.models import GraderSettings
        GraderSettings.objects.get_or_create(pk=1)
        pipeline.clear_auth_alert()
        # Test pks (1..N) collide with real submissions: keep the live-activity log
        # (and preview-port file) in the temp dir, never the repo's data/ tree.
        events = self.tmp / "events"
        self._events_patch = mock.patch(
            "codex_runner.activity.events_path",
            lambda config, sid: events / str(sid) / "events.jsonl",
        )
        self._events_patch.start()

    def tearDown(self) -> None:
        self._events_patch.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)
        pipeline.clear_auth_alert()

    def _drain(self, orch: Orchestrator) -> None:
        """Serial drain for tests that don't assert on generation concurrency:
        process every queued submission in-line, then wait for all scoring futures.
        Re-queued (rate-limited) submissions are picked up again. (Generation
        parallelism itself is covered by test_a_bounded_parallel_generation.)"""
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


class ParallelGenerationTests(PipelineTestBase):
    def test_a_bounded_parallel_generation(self) -> None:
        """(a) Generation runs in parallel but peak concurrency stays within
        generation_concurrency (and >1, i.e. it actually overlaps)."""
        cfg = _test_config(
            self.workdir_base, generation_concurrency=3, scoring_concurrency=3
        )
        gen = FakeGenerate(self.workdir_base, duration=0.1)
        grade = FakeGrade(duration=0.02)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        subs = [self.backend.enqueue(f"p{i}", f"prompt {i}") for i in range(6)]

        futures = [orch.submit_generation(s) for s in subs]
        for fut in futures:
            fut.result(timeout=20.0)
        orch.wait_for_scoring(timeout=20.0)
        orch.shutdown(wait=True)

        self.assertEqual(len(gen.intervals), 6)
        self.assertLessEqual(
            gen.peak_concurrency, cfg.generation_concurrency,
            f"peak generation concurrency {gen.peak_concurrency} exceeded cap "
            f"{cfg.generation_concurrency}",
        )
        self.assertGreater(
            gen.peak_concurrency, 1, "generation did not actually run in parallel"
        )
        self.assertEqual(
            Submission.objects.filter(status=Submission.Status.DONE).count(), 6
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

        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        sub = self.backend.enqueue("solo", "please generate")

        # First pass: hits rate limit, re-queues. Spy that RATE_LIMITED was entered.
        from submissions import state as st
        with mock.patch.object(pipeline.state, "to_rate_limited", wraps=st.to_rate_limited) as rl:
            orch.process_one(sub)
        rl.assert_called_once()
        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.QUEUED)
        self.assertEqual(sub.rate_limit_retries, 1)
        self.assertEqual(sub.generation_retries, 0)  # usage limit ≠ generation failure

        # Second pass: succeeds -> scoring -> done.
        nxt = self.backend.claim_next_queued()
        self.assertIsNotNone(nxt)
        orch.process_one(nxt)
        orch.wait_for_scoring(timeout=10.0)
        orch.shutdown(wait=True)

        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.DONE)
        self.assertEqual(sub.final_score, 72.5)


class RateLimitBudgetTests(PipelineTestBase):
    def test_rate_limits_never_use_up_the_generation_retry_budget(self) -> None:
        # generation_max=2: two usage-limit hits + one transient generation error must
        # still end DONE — rate limits are not failures.
        cfg = _test_config(self.workdir_base, generation_max=2)
        rl = RateLimitError(retry_after=0.0, detail="usage limit")
        gen = RaiseSequenceThenSucceedGenerate(
            self.workdir_base, [rl, rl, GenerationError(detail="transient")], duration=0.01)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=FakeGrade(duration=0.01))
        sub = self.backend.enqueue("solo", "please generate")
        self._drain(orch)
        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.DONE)
        self.assertEqual((sub.rate_limit_retries, sub.generation_retries), (2, 1))


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


class ContractFailureTests(PipelineTestBase):
    def test_contract_failure_fails_once_and_is_never_graded(self) -> None:
        """An app that never passed the functional contract in the Codex budget is a
        final generation failure: failed with a short reason, one generate call, no
        re-queue, no scoring."""
        cfg = _test_config(self.workdir_base, generation_max=3)
        gen = CountingGenerate(self.workdir_base, ContractFailedError(detail="28/30 at deadline"))
        grade = FakeGrade(duration=0.01)
        orch = Orchestrator(cfg, generate_fn=gen, grade_fn=grade)
        sub = self.backend.enqueue("solo", "generate please")
        orch.process_one(sub)
        orch.shutdown(wait=True)

        sub.refresh_from_db()
        self.assertEqual(sub.status, Submission.Status.FAILED)
        self.assertEqual(sub.last_error, "생성한 앱이 시간 안에 기능 테스트를 모두 통과하지 못했습니다.")
        self.assertNotIn("(", sub.last_error)
        self.assertEqual(gen.count, 1, "a contract failure must not be regenerated")
        self.assertEqual(grade.calls, [], "a contract failure must not be graded")
        self.assertEqual(
            Submission.objects.filter(status=Submission.Status.QUEUED).count(), 0
        )


class WorkerCommandTests(PipelineTestBase):
    """Drive the REAL ``run_worker`` loop (not submit_generation directly) to
    settle two doubts: (1) is generation actually parallel? (2) is the queue
    drained FIFO and fully?"""

    def _run_worker_once(self, cfg, gen, grade) -> None:
        with mock.patch.object(OrchestratorConfig, "from_scoring_config", return_value=cfg), \
             mock.patch.object(pipeline, "_default_generate_fn", return_value=gen), \
             mock.patch.object(pipeline, "_default_grade_fn", return_value=grade):
            call_command("run_worker", "--once")

    def test_run_worker_parallelizes_and_drains_queue_fifo(self) -> None:
        cfg = _test_config(
            self.workdir_base, generation_concurrency=4, scoring_concurrency=4,
            poll_interval_seconds=0.01,
        )
        gen = FakeGenerate(self.workdir_base, duration=0.15)
        grade = FakeGrade(duration=0.02)
        subs = [self.backend.enqueue(f"p{i}", f"prompt {i}") for i in range(8)]

        self._run_worker_once(cfg, gen, grade)

        # (2) queue fully drained, every submission done.
        self.assertEqual(
            Submission.objects.filter(status=Submission.Status.DONE).count(), 8
        )
        self.assertEqual(
            Submission.objects.filter(status=Submission.Status.QUEUED).count(), 0
        )
        # (1) generation genuinely overlapped, but never above the pool cap.
        self.assertGreater(
            gen.peak_concurrency, 1, "run_worker did NOT parallelize generation"
        )
        self.assertLessEqual(gen.peak_concurrency, cfg.generation_concurrency)
        # FIFO: the first `generation_concurrency` to START are the first enqueued
        # (later ones can't dispatch until an earlier slot frees ~0.15s later).
        started = [iv.submission_id for iv in sorted(gen.intervals, key=lambda i: i.start)]
        self.assertEqual(
            set(started[:4]), {str(s.pk) for s in subs[:4]}, "queue not claimed FIFO"
        )

    def test_codex_max_sessions_throttles_generation(self) -> None:
        # Admin setting below the pool ceiling must cap live concurrency.
        s = GraderSettings.load()
        s.codex_max_sessions = 2
        s.save()
        cfg = _test_config(
            self.workdir_base, generation_concurrency=5, scoring_concurrency=5,
            poll_interval_seconds=0.01,
        )
        gen = FakeGenerate(self.workdir_base, duration=0.12)
        grade = FakeGrade(duration=0.02)
        for i in range(6):
            self.backend.enqueue(f"p{i}", f"prompt {i}")

        self._run_worker_once(cfg, gen, grade)

        self.assertEqual(
            Submission.objects.filter(status=Submission.Status.DONE).count(), 6
        )
        self.assertLessEqual(
            gen.peak_concurrency, 2,
            f"codex_max_sessions=2 did not throttle (peak={gen.peak_concurrency})",
        )




class PromptEfficiencyTests(PipelineTestBase):
    def test_long_participant_prompt_scales_the_final_score(self) -> None:
        """The efficiency multiplier uses the PARTICIPANT's prompt length (not the
        system prompt): 600 chars → ×0.9 of the security score."""
        cfg = _test_config(self.workdir_base)
        orch = Orchestrator(cfg, generate_fn=FakeGenerate(self.workdir_base, duration=0.01),
                            grade_fn=FakeGrade(duration=0.01))
        long_sub = self.backend.enqueue("long", "SYSTEM\n\n" + "가" * 600, "가" * 600)
        short_sub = self.backend.enqueue("short", "SYSTEM\n\n" + "가" * 150, "가" * 150)
        for s in (long_sub, short_sub):
            orch.process_one(s)
        orch.wait_for_scoring(timeout=10.0)
        orch.shutdown(wait=True)

        long_sub.refresh_from_db()
        short_sub.refresh_from_db()
        self.assertEqual(long_sub.security_score, 72.5)
        self.assertEqual(long_sub.prompt_chars, 600)
        self.assertAlmostEqual(long_sub.efficiency, 0.9)
        self.assertAlmostEqual(long_sub.final_score, 65.25)
        self.assertEqual(short_sub.final_score, 72.5)  # within the free length
        self.assertEqual(short_sub.efficiency, 1.0)
