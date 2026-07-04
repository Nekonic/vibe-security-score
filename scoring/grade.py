"""Queue-facing entrypoint for the grading engine."""
from __future__ import annotations

from typing import List, Optional

from .aggregate import combine_scores
from .config import Config, load_config
from .models import CheckResult, GradeResult
from .static.runner import run_static


def _flatten_findings(result: GradeResult) -> List[dict]:
    findings: List[dict] = []
    for cat in result.categories:
        for c in cat.checks:
            findings.append(c.to_dict())
    return findings


def build_report(submission_id: str, result: GradeResult) -> dict:
    return {
        "submission_id": submission_id,
        "final_score": round(float(result.score), 2),
        "grade": result.grade,
        "pass_fail": "PASS" if result.passed else "FAIL",
        "passed": bool(result.passed),
        "capped": bool(result.capped),
        "cap_reason": result.cap_reason,
        "functional_failed": bool(result.functional_failed),
        "boot_failed": bool(result.boot_failed),
        "findings": _flatten_findings(result),
    }


def grade_submission(
    submission_id: str,
    code_dir: str,
    config: Optional[Config] = None,
    *,
    static_only: bool = False,
) -> dict:
    """Grade one project dir. Dynamic phase runs unless static_only (needs Docker).

    Infrastructure errors from the dynamic phase propagate (not swallowed) so the
    orchestrator can tell an operational failure from an app that failed to boot.
    """
    cfg = config or load_config()

    checks: List[CheckResult] = list(run_static(code_dir, cfg))
    functional_failed = False
    boot_failed = False

    if not static_only:
        # Lazy import: keeps dynamic deps (requests/docker) off static-only hosts.
        from .dynamic.runner import run_dynamic

        dyn_checks, functional_failed, boot_failed = run_dynamic(code_dir, cfg)
        checks.extend(dyn_checks)

    result = combine_scores(
        checks,
        cfg,
        functional_failed=functional_failed,
        boot_failed=boot_failed,
    )
    return build_report(submission_id, result)
