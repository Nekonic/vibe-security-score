"""Operator dashboard (Django admin). Full findings shown (operator side).
Lifecycle changes go through ``submissions.state``, never inline."""
from __future__ import annotations

from django.contrib import admin
from django.db.models import Count
from django.utils.html import format_html, format_html_join

from .models import Submission
from . import state


@admin.register(Submission)
class SubmissionAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "participant",
        "colored_status",
        "queue_pos",
        "final_score",
        "grade",
        "pass_fail",
        "submitted_at",
    )
    list_filter = ("status", "pass_fail")
    search_fields = ("participant", "prompt")
    date_hierarchy = "submitted_at"
    ordering = ("-submitted_at",)
    actions = ("regrade",)
    readonly_fields = (
        "submitted_at",
        "final_score",
        "grade",
        "pass_fail",
        "findings_pretty",
        "findings",
        "generation_retries",
        "scoring_retries",
        "last_error",
        "workdir",
        "queued_at",
        "generation_started_at",
        "generation_finished_at",
        "scoring_started_at",
        "finished_at",
    )

    _STATUS_COLOR = {
        Submission.Status.QUEUED: "#7aa2ff",
        Submission.Status.RATE_LIMITED: "#ffcf5c",
        Submission.Status.GENERATING: "#7aa2ff",
        Submission.Status.SCORING: "#7aa2ff",
        Submission.Status.DONE: "#37d19a",
        Submission.Status.FAILED: "#ff6b81",
    }

    @admin.display(description="상태", ordering="status")
    def colored_status(self, obj: Submission):
        color = self._STATUS_COLOR.get(obj.status, "#888")
        return format_html(
            '<b style="color:{}">{}</b>', color, obj.get_status_display()
        )

    @admin.display(description="대기순번")
    def queue_pos(self, obj: Submission):
        pos = obj.queue_position()
        return pos if pos else "-"

    @admin.display(description="채점 결과")
    def findings_pretty(self, obj: Submission):
        findings = obj.findings or []
        if not findings:
            return "-"
        rows = []
        for f in findings:
            if f.get("skipped"):
                mark, color = "○", "#9aa4bf"
            elif f.get("passed"):
                mark, color = "✔", "#2a9d6f"
            else:
                mark, color = "✘", "#c0392b"
            reasons = "; ".join(f.get("penalty_reasons", []) or [])
            rows.append(
                (
                    color,
                    mark,
                    f.get("label") or f.get("check_id", ""),
                    f.get("score", ""),
                    f.get("weight", ""),
                    reasons,
                )
            )
        return format_html(
            '<table style="border-collapse:collapse">{}</table>',
            format_html_join(
                "",
                '<tr><td style="color:{};padding:2px 8px">{}</td>'
                '<td style="padding:2px 8px"><b>{}</b></td>'
                '<td style="padding:2px 8px">{} / 100</td>'
                '<td style="padding:2px 8px;color:#888">w={}</td>'
                '<td style="padding:2px 8px;color:#a80">{}</td></tr>',
                rows,
            ),
        )

    @admin.action(description="재채점")
    def regrade(self, request, queryset):
        # Re-score existing generated code. NEVER calls Codex — the worker fails a
        # submission whose code is gone rather than regenerating it.
        n = 0
        for sub in queryset.filter(
            status__in=(Submission.Status.DONE, Submission.Status.FAILED)
        ):
            sub.regrade_only = True
            sub.last_error = ""
            sub.finished_at = None
            sub.save(update_fields=["regrade_only", "last_error", "finished_at"])
            state.back_to_queued(sub)
            n += 1
        self.message_user(request, f"{n}건 재채점")

    def changelist_view(self, request, extra_context=None):
        counts = {
            row["status"]: row["n"]
            for row in Submission.objects.values("status").annotate(n=Count("id"))
        }
        labels = dict(Submission.Status.choices)
        summary = [(labels.get(s, s), counts.get(s, 0)) for s, _ in Submission.Status.choices]
        extra_context = extra_context or {}
        extra_context["status_summary"] = summary
        extra_context["queued_total"] = counts.get(Submission.Status.QUEUED, 0)
        return super().changelist_view(request, extra_context=extra_context)
