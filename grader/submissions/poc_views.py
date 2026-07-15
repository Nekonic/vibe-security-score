"""Operator-only PoC (attack-demonstration) console views. Kept out of the
participant views: these boot isolated containers and run confirmed exploits,
and are all staff-gated."""
from __future__ import annotations

import json

from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from . import poc_session
from .models import Submission
from .poc import poc_terminals
from .rubric import visible_findings


@staff_member_required
def poc_console(request, pk: int):
    """운영자 전용 공격 시연 콘솔: 확인된 취약점을 격리 컨테이너에서 실제로 공격해
    보인다. 채점이 끝난 제출만 대상."""
    sub = get_object_or_404(Submission, pk=pk)
    if sub.status != Submission.Status.DONE:
        return redirect("submissions:result", pk=pk)
    visible = visible_findings(sub)
    # terminals cross-references ALL findings (incl. weight-0 session_forgery) so a
    # replay PoC only appears when a verified forged cookie exists.
    terminals = poc_terminals(visible, sub.findings)
    poc_ids = {t["check_id"] for t in terminals}
    items = []
    for f in visible:
        f = dict(f)
        # Badge tracks the tabs that were actually built (forgery tabs are gated on
        # a verified cookie), so the "has_poc" chip never promises a missing tab.
        f["has_poc"] = f.get("check_id") in poc_ids
        items.append(f)
    return render(request, "submissions/poc_console.html", {
        "sub": sub,
        "items": items,
        "terminals": terminals,
    })


def _poc_target(request, pk: int):
    """Shared guard for the PoC live endpoints: staff-only, DONE + workdir present."""
    sub = get_object_or_404(Submission, pk=pk)
    if sub.status != Submission.Status.DONE or not sub.workdir:
        return None, JsonResponse(
            {"ok": False, "error": "채점이 끝났고 생성 코드가 남아 있는 제출만 시연할 수 있습니다."},
            status=400,
        )
    return sub, None


@staff_member_required
@require_POST
def poc_start(request, pk: int):
    sub, err = _poc_target(request, pk)
    if err is not None:
        return err
    return JsonResponse(poc_session.start(sub))


@staff_member_required
@require_POST
def poc_run(request, pk: int):
    sub, err = _poc_target(request, pk)
    if err is not None:
        return err
    try:
        body = json.loads(request.body.decode("utf-8") or "{}")
    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"ok": False, "error": "잘못된 요청 본문입니다."}, status=400)
    check_id = str(body.get("check_id") or "")
    code = str(body.get("code") or "")
    if not check_id or not code.strip():
        return JsonResponse({"ok": False, "error": "check_id 와 code 가 필요합니다."}, status=400)
    return JsonResponse(poc_session.run(sub, check_id, code))


@staff_member_required
@require_POST
def poc_stop(request, pk: int):
    sub = get_object_or_404(Submission, pk=pk)
    return JsonResponse(poc_session.stop(sub))
