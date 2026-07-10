"""Fake generate_fn / grade_fn for hermetic tests (no Docker/Codex). Create real
temp dirs and record intervals + live concurrency for the policy assertions."""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple


class Interval:
    __slots__ = ("submission_id", "start", "end")

    def __init__(self, submission_id: str, start: float, end: float):
        self.submission_id = submission_id
        self.start = start
        self.end = end

    def overlaps(self, other: "Interval") -> bool:
        return self.start < other.end and other.start < self.end


class FakeGenerate:
    """Records generation start/end wall times; creates a real workdir per call."""

    def __init__(self, workdir_base: Path, *, duration: float = 0.05):
        self.workdir_base = Path(workdir_base)
        self.duration = duration
        self.intervals: List[Interval] = []
        self._lock = threading.Lock()

    def __call__(self, submission_id: str, prompt: str, *, config=None, event_sink=None) -> Path:
        start = time.monotonic()
        time.sleep(self.duration)
        wd = self.workdir_base / f"sub-{submission_id}"
        wd.mkdir(parents=True, exist_ok=True)
        (wd / "app.py").write_text("# fake generated app\n", encoding="utf-8")
        (wd / "prompt.md").write_text(prompt, encoding="utf-8")
        end = time.monotonic()
        with self._lock:
            self.intervals.append(Interval(submission_id, start, end))
        return wd

    def any_overlap(self) -> bool:
        ivs = sorted(self.intervals, key=lambda i: i.start)
        for a, b in zip(ivs, ivs[1:]):
            if a.overlaps(b):
                return True
        return False


class FakeGrade:
    """Records live scoring concurrency; returns a canned report dict."""

    def __init__(self, *, duration: float = 0.1, report: Optional[dict] = None):
        self.duration = duration
        self._report = report
        self._live = 0
        self._peak = 0
        self._lock = threading.Lock()
        self.calls: List[str] = []

    def __call__(self, submission_id: str, code_dir: str, config=None) -> dict:
        with self._lock:
            self._live += 1
            self._peak = max(self._peak, self._live)
            self.calls.append(submission_id)
        try:
            time.sleep(self.duration)
        finally:
            with self._lock:
                self._live -= 1
        if self._report is not None:
            return dict(self._report)
        return {
            "submission_id": submission_id,
            "final_score": 72.5,
            "grade": "통과",
            "pass_fail": "pass",
            "passed": True,
            "capped": False,
            "cap_reason": "",
            "functional_failed": False,
            "boot_failed": False,
            "findings": [{"id": "demo", "detail": "ok"}],
        }

    @property
    def peak_concurrency(self) -> int:
        return self._peak


class RaiseOnceThenSucceedGenerate(FakeGenerate):
    """Raises a given exception on the FIRST call, then behaves normally."""

    def __init__(self, workdir_base: Path, exc: Exception, *, duration: float = 0.02):
        super().__init__(workdir_base, duration=duration)
        self._exc = exc
        self._raised = False
        self._raise_lock = threading.Lock()

    def __call__(self, submission_id: str, prompt: str, *, config=None, event_sink=None) -> Path:
        with self._raise_lock:
            if not self._raised:
                self._raised = True
                raise self._exc
        return super().__call__(submission_id, prompt, config=config, event_sink=event_sink)


class FailForSubmissionGenerate(FakeGenerate):
    """Raises ``exc`` for one specific submission id; normal for all others."""

    def __init__(self, workdir_base: Path, fail_id: str, exc: Exception, *, duration: float = 0.02):
        super().__init__(workdir_base, duration=duration)
        self._fail_id = str(fail_id)
        self._exc = exc

    def __call__(self, submission_id: str, prompt: str, *, config=None, event_sink=None) -> Path:
        if str(submission_id) == self._fail_id:
            raise self._exc
        return super().__call__(submission_id, prompt, config=config, event_sink=event_sink)


class CountingGenerate(FakeGenerate):
    """Always raises ``exc``; counts how many times it was called (retry probe)."""

    def __init__(self, workdir_base: Path, exc: Exception, *, duration: float = 0.0):
        super().__init__(workdir_base, duration=duration)
        self._exc = exc
        self.count = 0
        self._count_lock = threading.Lock()

    def __call__(self, submission_id: str, prompt: str, *, config=None, event_sink=None) -> Path:
        with self._count_lock:
            self.count += 1
        raise self._exc
