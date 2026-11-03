"""Replay every dynamic check of graded submissions in a real Kali session and
compare each verdict with the stored grade (``kali_poc.py --all``).

    uv run python manage.py verify_kali            # every DONE submission
    uv run python manage.py verify_kali 14 9       # these ids

Needs the vibe-sec-sandbox and vibe-sec-attack images. Exit code 1 on any mismatch,
on a session that did not start, on a replay that failed to run, and when nothing
was compared. Each session is removed before the next starts and before exit.
"""
from __future__ import annotations

import subprocess
import time

from django.core.management.base import BaseCommand

from submissions import kali_session
from submissions.models import Submission

_BOOT_WAIT = 600


class Command(BaseCommand):
    help = "Kali 재현 판정을 저장된 채점 결과와 대조"

    def add_arguments(self, parser):
        parser.add_argument("ids", nargs="*", type=int)

    def handle(self, *args, ids, **options):
        subs = Submission.objects.filter(status=Submission.Status.DONE).order_by("pk")
        if ids:
            subs = subs.filter(pk__in=ids)
        compared = mismatched = failed = 0
        for sub in subs:
            started = kali_session.start(sub, watch_io=False)
            if not started.get("ok"):
                self.stdout.write(f"#{sub.pk} 세션 시작 실패 · {started.get('error', '')}")
                failed += 1
                continue
            sid = started["sid"]
            try:
                n, diffs, ok = self._replay(sub, sid)
            finally:
                kali_session.stop(sub.pk, sid, wait=True)
            compared += n
            mismatched += len(diffs)
            failed += 0 if ok else 1
            self.stdout.write(f"#{sub.pk} 대조 {n} · 불일치 {len(diffs)}" + "".join(f"\n  {d}" for d in diffs))
        self.stdout.write(f"대조 {compared}건 · 불일치 {mismatched}건 · 실패 {failed}건")
        if mismatched or failed or not compared:
            raise SystemExit(1)

    def _replay(self, sub, sid):
        """(compared, mismatch lines, ran cleanly) for one live session."""
        sess = kali_session.session(sub.pk, sid)
        t = time.time()
        while sess is not None and not sess.ready and not sess.closed and time.time() - t < _BOOT_WAIT:
            time.sleep(1)
        if sess is None or not sess.ready or sess.closed:
            out = bytes(sess.out).decode("utf-8", "replace")[-800:] if sess is not None else ""
            self.stdout.write(f"#{sub.pk} 세션 시작 실패\n{out}")
            return 0, [], False
        try:
            p = subprocess.run(["docker", "exec", sess.kali, "python", "/opt/vibe/kali_poc.py", "--all"],
                               capture_output=True, text=True, timeout=1200)
        except subprocess.TimeoutExpired:
            self.stdout.write(f"#{sub.pk} 재현 시간 초과")
            return 0, [], False
        lines = p.stdout.splitlines()
        diffs = [ln for ln in lines if ln.startswith("다름")]
        n = sum(1 for ln in lines if ln.startswith(("일치", "다름")))
        ok = p.returncode in (0, 1) and n > 0
        if not ok:
            self.stdout.write(f"#{sub.pk} 재현 실패 · 종료 코드 {p.returncode}\n{(p.stderr or p.stdout)[-800:]}")
        return n, diffs, ok
