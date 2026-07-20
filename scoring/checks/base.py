"""The Check declaration and the CheckResult builders shared by every family.

A Check couples a check/probe function to its id, display label, execution phase,
and the config subtree that holds its tunables. Family functions never re-spell
their own id/label/category/weight — they derive a CheckResult from the Check via
``result(...)`` (a decided verdict) or ``_undecidable(...)`` (could-not-test, so
excluded from aggregation). The OWASP tag is derived later in ``scoring.models``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..models import CheckResult
from ..shared.sources import _clamp


@dataclass(frozen=True)
class Check:
    id: str
    label: str
    phase: str  # "static" | "dynamic"
    fn: Callable
    # Dotted config subtree holding this check's tunables (weight, thresholds).
    # "" derives the default from the phase (static.checks / dynamic.checks); a
    # check whose config lives elsewhere states it (e.g. "static.dependencies").
    cfg_path: str = ""
    # Report-only checks (external SAST/secret tools) never score: weight is 0.
    report_only: bool = False
    # Standard checks take (check, ctx, cfg) and let the runner pass identity and wrap
    # exceptions. The two that opt out (standard=False) are invoked specially by the
    # runner: `sqli` must propagate its hard-fail, `functional` needs the gate wiring.
    standard: bool = True


def _default_cfg_path(phase: str) -> str:
    return "static.checks" if phase == "static" else "dynamic.checks"


def resolve_cfg(config, check: Check) -> dict:
    """This check's config dict, from ``check.cfg_path`` (or the phase default)."""
    path = check.cfg_path or _default_cfg_path(check.phase)
    return (config.get(path, {}) or {}).get(check.id, {}) or {}


def result(check: Check, cfg: dict, *, score, passed, reasons=(), evidence=(),
           tool: str = "", weight=None) -> CheckResult:
    """A decided verdict. Identity comes from ``check``; ``category`` is the phase.
    ``weight`` defaults to ``cfg['weight']`` (0 for report-only) — pass it only to
    override (e.g. a fixed score band)."""
    return CheckResult(
        check_id=check.id, category=check.phase, label=check.label,
        score=_clamp(float(score)),
        weight=_weight(check, cfg, weight),
        passed=passed, penalty_reasons=list(reasons),
        evidence=list(evidence), tool=tool,
    )


def _undecidable(check: Check, cfg: dict, reason: str, *, passed: bool = False,
                 tool: str = "", weight=None) -> CheckResult:
    """A check we could NOT reliably run. ``skipped=True`` so aggregation EXCLUDES
    it — scoring an untestable check as vulnerable would falsely penalize a defended
    app. Still reported so the operator sees why."""
    return CheckResult(
        check_id=check.id, category=check.phase, label=check.label,
        score=0.0,
        weight=_weight(check, cfg, weight),
        passed=passed, skipped=True,
        penalty_reasons=[f"검사 생략(판정 불가): {reason}"],
        evidence=[], tool=tool,
    )


def _weight(check: Check, cfg: dict, override) -> float:
    if check.report_only:
        return 0.0
    if override is not None:
        return float(override)
    return float(cfg.get("weight", 0))
