"""Queue-facing entrypoint for the grading engine."""
from __future__ import annotations

from typing import List, Optional

from . import progress as _progress
from . import registry
from .aggregate import combine_scores
from .config import Config, load_config
from .models import CheckResult, GradeResult
from .runner import run_static


def _flatten_findings(result: GradeResult) -> List[dict]:
    findings: List[dict] = []
    for cat in result.categories:
        for c in cat.checks:
            findings.append(c.to_dict())
    return findings


def build_report(submission_id: str, result: GradeResult, boot_log: str = "") -> dict:
    return {
        "submission_id": submission_id,
        "final_score": round(float(result.score), 2),
        "raw_score": round(float(result.raw_score), 2),
        "grade": result.grade,
        "pass_fail": "PASS" if result.passed else "FAIL",
        "passed": bool(result.passed),
        "capped": bool(result.capped),
        "cap_reason": result.cap_reason,
        "functional_failed": bool(result.functional_failed),
        "boot_failed": bool(result.boot_failed),
        "boot_log": boot_log or "",
        "critical_penalties": [p.to_dict() for p in result.critical_penalties],
        "categories": [c.to_dict() for c in result.categories],
        "findings": _flatten_findings(result),
    }


def grade_submission(
    submission_id: str,
    code_dir: str,
    config: Optional[Config] = None,
    *,
    static_only: bool = False,
    dev: bool = False,
) -> dict:
    """Grade one project dir. Dynamic phase runs unless static_only (needs Docker).

    ``dev=True`` runs the real external tools (osv-scanner/gitleaks/semgrep/sqlmap);
    default False uses the built-in offline checks and warns.

    Infrastructure errors from the dynamic phase propagate (not swallowed) so the
    orchestrator can tell an operational failure from an app that failed to boot.
    """
    cfg = config or load_config()
    if dev:
        cfg.dev = True
    if not cfg.dev:
        from .shared.external_tools import missing_required_tools

        missing = missing_required_tools(cfg)
        if missing:
            raise RuntimeError(
                "필수 외부 도구 미설치: " + ", ".join(missing)
                + ". 설치하거나 dev=True 로 실행하세요(내장 검사, 권장하지 않음)."
            )

    # Progress: total checks across both phases, ticked as each completes so the
    # result page can show "몇 % · 어느 검사 중". Best-effort (never breaks grading).
    n_static = len(registry.by_phase("static"))
    n_dynamic = 0 if static_only else len(registry.by_phase("dynamic")) + 1  # +1 = CVE recompute
    total = n_static + n_dynamic
    _state = {"done": 0}

    def _tick(phase: str):
        def _cb(label: str):
            _state["done"] += 1
            _progress.write(cfg, submission_id, phase=phase, done=_state["done"],
                            total=total, label=label)
        return _cb

    _progress.write(cfg, submission_id, phase="static", done=0, total=total, label="정적 분석 시작")
    functional_failed = False
    boot_failed = False
    boot_log = ""

    if static_only:
        # static_only has no dynamic CVE recompute, so the static osv run is the
        # ONLY CVE source here — keep it (explicit False guards a shared config that
        # a prior full grade may have flipped to True).
        cfg.skip_static_osv = False
        checks: List[CheckResult] = list(run_static(code_dir, cfg, on_check=_tick("static")))
    else:
        # Lazy import: keeps dynamic deps (requests/docker) off static-only hosts.
        from concurrent.futures import ThreadPoolExecutor
        from .runner import boot_sandbox, run_dynamic

        # Boot the sandbox container CONCURRENTLY with the static phase: the ~5–9s
        # docker boot is pure dead-wait, so we hide it behind static analysis.
        # ``skip_static_osv`` then drops the static osv-scanner subprocess — the
        # dynamic pip-freeze recompute supersedes it (aggregate._dedupe_cve) and a
        # boot failure caps the score to 0 (gates.boot.fail_cap), so it's pure waste.
        cfg.skip_static_osv = True
        boot_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="boot")
        boot_future = boot_pool.submit(boot_sandbox, code_dir, cfg)
        box = None
        try:
            checks = list(run_static(code_dir, cfg, on_check=_tick("static")))
            box = boot_future.result()  # boot_sandbox never raises (boot_failed flag)
            dyn_checks, functional_failed, boot_failed, boot_log = run_dynamic(
                code_dir, cfg, on_check=_tick("dynamic"), box=box
            )
            checks.extend(dyn_checks)
        finally:
            # Always tear the container down, even if static raised before the join.
            if box is None:
                try:
                    box = boot_future.result(timeout=120)
                except Exception:  # pragma: no cover - defensive
                    box = None
            if box is not None:
                box.__exit__(None, None, None)
            boot_pool.shutdown(wait=False)

    _progress.write(cfg, submission_id, phase="done", done=total, total=total, label="채점 완료")
    result = combine_scores(
        checks,
        cfg,
        functional_failed=functional_failed,
        boot_failed=boot_failed,
    )
    return build_report(submission_id, result, boot_log)
