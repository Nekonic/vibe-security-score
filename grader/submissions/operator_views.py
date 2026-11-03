"""Operator-only views: the generated app.py in a code viewer, and the Kali console
that attacks the graded app (grader/submissions/kali_session.py). All staff-gated."""
from __future__ import annotations

import json
import pathlib
import subprocess

from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from . import kali_session
from .models import Submission


# Code viewer: the challenge is one app.py, so that file is all it shows.
_CODE_MAX_BYTES = 300_000


def _app_code(workdir: str):
    p = pathlib.Path(workdir) / "app.py"
    if p.is_symlink() or not p.is_file() or p.stat().st_size > _CODE_MAX_BYTES:
        return None
    try:
        return _formatted(p.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, OSError):
        return None


def _formatted(code: str) -> str:
    """Codex packs app.py (1-space indents, `a;b` lines): show it ruff-formatted with
    4-space indents. Display only; the file is untouched. Raw text if ruff can't parse it."""
    from ruff import find_ruff_bin
    try:
        out = subprocess.run([find_ruff_bin(), "format", "--stdin-filename", "app.py", "-"],
                             input=code, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return code
    return out.stdout if out.returncode == 0 and out.stdout else code


@staff_member_required
def code_view(request, pk: int):
    """운영자 전용 코드 보기: 생성된 app.py를 읽기 전용 편집기로 보여준다."""
    sub = get_object_or_404(Submission, pk=pk)
    code = _app_code(sub.workdir) if sub.workdir else None
    return render(request, "submissions/code.html", {"sub": sub, "code": code})


# Kali console: only a graded submission whose code is still on disk.
def _kali_target(pk: int):
    sub = get_object_or_404(Submission, pk=pk)
    ok = sub.status == Submission.Status.DONE and sub.workdir and pathlib.Path(sub.workdir).is_dir()
    return sub, ok


@staff_member_required
def kali_console(request, pk: int):
    sub, ok = _kali_target(pk)
    if not ok:
        return redirect("submissions:result", pk=pk)
    return render(request, "submissions/kali.html", {"sub": sub})


@staff_member_required
@require_POST
def kali_start(request, pk: int):
    sub, ok = _kali_target(pk)
    if not ok:
        return JsonResponse({"ok": False, "error": "생성 코드 없음"}, status=400)
    return JsonResponse(kali_session.start(sub))


@staff_member_required
@require_POST
def kali_io(request, pk: int):
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"ok": False}, status=400)
    return JsonResponse(kali_session.io(
        pk, str(body.get("sid") or ""), data=str(body.get("data") or ""), since=int(body.get("since") or 0),
        cols=int(body.get("cols") or 0), rows=int(body.get("rows") or 0)))


@staff_member_required
@require_POST
def kali_stop(request, pk: int):
    # The pagehide beacon names its own session, so a page never stops a newer one.
    return JsonResponse(kali_session.stop(pk, request.POST.get("sid", "")))
