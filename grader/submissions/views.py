"""Participant-facing web UI. Only creates queued submissions and reads
status/results; the worker does all processing. Security checks are never
disclosed pre-grading (findings appear only on the result screen)."""
from __future__ import annotations

from functools import lru_cache

from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth.views import redirect_to_login
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from . import rubric, state
from .models import Submission
from .orchestrator.queue_backend import DBQueueBackend


@lru_cache(maxsize=1)
def _default_prompt() -> str:
    path = settings.REPO_ROOT / "config" / "default_prompt.md"
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


def _build_prompt(user_prompt: str) -> str:
    """Codex prompt = the fixed system prompt (app contract) + the participant's
    prompt. The system prompt is always server-side, never trusted from the
    client, so the app contract the probes assume can't be altered."""
    return f"{_default_prompt().rstrip()}\n\n{user_prompt.strip()}\n"


def _max_prompt_chars() -> int:
    """Config cap (characters incl. whitespace) on the participant's prompt; 0 => no limit."""
    try:
        from scoring.config import load_config
        return int(load_config().get("submission.max_prompt_chars", 0) or 0)
    except Exception:
        return 0


def submit(request):
    if request.method == "POST":
        # Submitting costs a Codex call — gate it to logged-in accounts.
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path())
        user_prompt = (request.POST.get("prompt") or "").strip()
        if not user_prompt:
            return render(
                request,
                "submissions/submit.html",
                {"system_prompt": _default_prompt(), "prompt": user_prompt,
                 "error": "프롬프트를 입력해 주세요."},
                status=400,
            )
        limit = _max_prompt_chars()
        size = len(user_prompt)
        if limit and size > limit:
            return render(
                request,
                "submissions/submit.html",
                {"system_prompt": _default_prompt(), "prompt": user_prompt,
                 "error": f"프롬프트가 너무 깁니다 ({size} / {limit}자). "
                          f"{limit}자 이하로 줄여 주세요.",
                 "max_prompt_chars": limit},
                status=400,
            )
        sub = DBQueueBackend().enqueue(_participant(request), _build_prompt(user_prompt))
        return redirect("submissions:result", pk=sub.pk)

    return render(
        request,
        "submissions/submit.html",
        {"system_prompt": _default_prompt(), "prompt": "",
         "max_prompt_chars": _max_prompt_chars()},
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


def result(request, pk: int):
    sub = get_object_or_404(Submission, pk=pk)
    done = sub.status == Submission.Status.DONE
    ctx = {
        "sub": sub,
        "stage_label": sub.get_status_display(),
        "stage_hint": _STAGE_HINT.get(sub.status, ""),
        "queue_position": sub.queue_position(),
        "done": done,
        "failed": sub.status == Submission.Status.FAILED,
        "boot_log": sub.boot_log if done else "",
        "findings": rubric.visible_findings(sub) if done else [],
        "category_groups": rubric.category_groups(sub) if done else [],
        "critical_penalties": (sub.critical_penalties or []) if done else [],
    }
    return render(request, "submissions/result.html", ctx)


@lru_cache(maxsize=1)
def _scoring_config():
    from scoring.config import load_config
    return load_config()


def generation_events_json(request, pk: int):
    """Live, redacted codex activity for the real-time generation view. Polled by
    the result page while generating; returns only items after ``since``."""
    sub = get_object_or_404(Submission, pk=pk)
    try:
        since = max(0, int(request.GET.get("since", 0)))
    except (TypeError, ValueError):
        since = 0
    items = []
    try:
        from codex_runner.activity import read_activity
        items = read_activity(_scoring_config(), str(sub.pk))
    except Exception:
        items = []
    return JsonResponse(
        {
            "events": items[since:],
            "next": len(items),
            "generating": sub.status == Submission.Status.GENERATING,
            "done": sub.is_terminal,
        }
    )


@staff_member_required
@require_POST
def rerun(request, pk: int):
    """Operator-only RE-GRADE: re-score the existing generated code. NEVER calls
    Codex — if the code is gone the worker fails the submission (it will not
    regenerate). Requires a logged-in staff operator."""
    sub = get_object_or_404(Submission, pk=pk)
    sub.regrade_only = True
    sub.last_error = ""
    sub.finished_at = None
    state.save_fields(sub, "regrade_only", "last_error", "finished_at")
    state.back_to_queued(sub)
    return redirect("submissions:result", pk=pk)


def status_json(request, pk: int):
    sub = get_object_or_404(Submission, pk=pk)
    progress = None
    if sub.status == Submission.Status.SCORING:
        from scoring import progress as _sp
        progress = _sp.read(_scoring_config(), str(sub.pk))
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
            "progress": progress,  # {pct,label,phase,done,total} during SCORING, else null
            "done": sub.is_terminal,  # done OR failed -> stop polling / reload
        }
    )


LEADERBOARD_SIZE = 50


def leaderboard(request):
    """Public ranking (viewable without login) — each participant's best completed
    submission by score. Aggregate only (no per-check findings)."""
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
