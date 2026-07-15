"""General SAST (no single OWASP category): semgrep auxiliary findings
(report-only, weight 0).
"""
from __future__ import annotations

from typing import List, Tuple

from ..models import CheckResult
from ..shared.external_tools import (
    _SKIP_REASON, _gate, _run_json, _skipped, _stub_command, _tool_cfg,
)
from .base import Check


def check_semgrep(app_dir: str, config) -> CheckResult:
    tcfg = _tool_cfg(config, "semgrep")
    label = "정적 룰셋(semgrep)"
    bin_path, skip = _gate(config, "semgrep")
    if bin_path is None:
        return _skipped("semgrep", label, "semgrep", skip or _SKIP_REASON)

    ruleset = tcfg.get("ruleset", "p/security-audit")
    cmd = _stub_command(bin_path) + ["--config", ruleset, "--json", "--quiet", app_dir]
    data = _run_json(cmd, float(tcfg.get("timeout", 120)))
    if data is None:
        data = {"results": []}

    reasons, evidence = _parse_semgrep(data)
    return CheckResult(
        check_id="semgrep",
        category="static",
        label=label,
        score=0.0 if reasons else 100.0,
        weight=0.0,
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
        skipped=False,
        tool="semgrep",
    )


def _parse_semgrep(data: object) -> Tuple[List[str], List[str]]:
    reasons: List[str] = []
    evidence: List[str] = []
    if not isinstance(data, dict):
        return reasons, evidence
    for r in (data.get("results", []) or []):
        if not isinstance(r, dict):
            continue
        check_id = r.get("check_id", "semgrep-rule")
        path = r.get("path", "")
        start = (r.get("start", {}) or {}).get("line", "")
        loc = f"{path}:{start}" if path else ""
        msg = (r.get("extra", {}) or {}).get("message", "") or check_id
        reasons.append(f"{loc} {check_id}".strip())
        evidence.append(f"{loc}: {msg}".strip())
    return reasons, evidence


CHECKS = [
    Check("semgrep", "정적 룰셋(semgrep)", "static",
            lambda sctx, cfg: check_semgrep(sctx.app_dir, sctx.config)),
]
