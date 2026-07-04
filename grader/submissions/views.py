"""Participant-facing web UI. Only creates queued submissions and reads
status/results; the worker does all processing. Security checks are never
disclosed pre-grading (findings appear only on the result screen)."""
from __future__ import annotations

from functools import lru_cache

from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .models import Submission
from .orchestrator.queue_backend import DBQueueBackend


@lru_cache(maxsize=1)
def _default_prompt() -> str:
    path = settings.REPO_ROOT / "config" / "default_prompt.txt"
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return "Flask로 간단한 게시판 웹앱을 만들어줘."


def _participant(request) -> str:
    """Stable per-visitor id: the provided nickname, else the session key."""
    if not request.session.session_key:
        request.session.create()
    nickname = (request.POST.get("nickname") or "").strip()
    return nickname or f"세션:{request.session.session_key[:8]}"


def submit(request):
    if request.method == "POST":
        prompt = (request.POST.get("prompt") or "").strip()
        if not prompt:
            return render(
                request,
                "submissions/submit.html",
                {"prompt": _default_prompt(), "error": "프롬프트를 입력해 주세요."},
                status=400,
            )
        sub = DBQueueBackend().enqueue(_participant(request), prompt)
        return redirect("submissions:result", pk=sub.pk)

    return render(
        request,
        "submissions/submit.html",
        {"prompt": _default_prompt()},
    )


# Stage descriptions shown to the participant (progress, not the checks).
_STAGE_HINT = {
    Submission.Status.QUEUED: "대기열에서 순서를 기다리고 있어요.",
    Submission.Status.RATE_LIMITED: "생성 한도 회복을 기다리는 중이에요. 잠시만요.",
    Submission.Status.GENERATING: "AI가 코드를 생성하고 있어요.",
    Submission.Status.SCORING: "생성된 코드를 채점하고 있어요.",
    Submission.Status.DONE: "채점이 끝났어요.",
    Submission.Status.FAILED: "처리 중 문제가 발생했어요.",
}


def _visible_findings(sub: Submission):
    """Scored findings only (drop skipped + zero-weight aux), worst-first."""
    items = [
        f
        for f in (sub.findings or [])
        if not f.get("skipped") and float(f.get("weight", 0) or 0) > 0
    ]
    items.sort(key=lambda f: (f.get("passed") is True, f.get("score", 0)))
    return items


def result(request, pk: int):
    sub = get_object_or_404(Submission, pk=pk)
    ctx = {
        "sub": sub,
        "stage_label": sub.get_status_display(),
        "stage_hint": _STAGE_HINT.get(sub.status, ""),
        "queue_position": sub.queue_position(),
        "done": sub.status == Submission.Status.DONE,
        "failed": sub.status == Submission.Status.FAILED,
        "findings": _visible_findings(sub) if sub.status == Submission.Status.DONE else [],
    }
    return render(request, "submissions/result.html", ctx)


def status_json(request, pk: int):
    sub = get_object_or_404(Submission, pk=pk)
    return JsonResponse(
        {
            "id": sub.pk,
            "status": sub.status,
            "stage_label": sub.get_status_display(),
            "stage_hint": _STAGE_HINT.get(sub.status, ""),
            "queue_position": sub.queue_position(),
            "final_score": sub.final_score,
            "grade": sub.grade,
            "pass_fail": sub.pass_fail,
            "done": sub.is_terminal,  # done OR failed -> stop polling / reload
        }
    )


LEADERBOARD_SIZE = 50


def leaderboard(request):
    """Public ranking: each participant's best completed submission, by score.
    Aggregate only (no per-check findings, so checks stay undisclosed)."""
    done = (
        Submission.objects.filter(
            status=Submission.Status.DONE, final_score__isnull=False
        )
        .order_by("-final_score", "finished_at")
    )
    rows = []
    seen = set()
    for sub in done:
        if sub.participant in seen:  # keep each participant's best (first = highest)
            continue
        seen.add(sub.participant)
        rows.append(sub)
        if len(rows) >= LEADERBOARD_SIZE:
            break
    return render(request, "submissions/leaderboard.html", {"rows": rows})
