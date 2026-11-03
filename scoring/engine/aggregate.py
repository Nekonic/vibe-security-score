"""Combine per-check results into category scores and a final GradeResult."""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from ..config import Config
from ..models import (
    CategoryResult, CheckResult, CriticalPenalty, GradeResult, code_for,
)


def _dedupe_cve(checks: List[CheckResult]) -> List[CheckResult]:
    """Prefer the resolved (pip-freeze/transitive) CVE result over the static
    requirements-only one when both are present, so A03 isn't double-counted."""
    if any(c.check_id == "cve" and "freeze" in c.tool for c in checks):
        return [c for c in checks if not (c.check_id == "cve" and "freeze" not in c.tool)]
    return checks


def _tag_owasp(checks: List[CheckResult]) -> None:
    for c in checks:
        if not c.owasp:
            c.owasp = code_for(c.check_id)


def _assign_categories(checks: List[CheckResult], config: Config) -> None:
    """Re-bucket every check into its config-defined rubric category (and stamp the
    human label). Operators can move any check between categories in config alone."""
    cat_map = config.category_map
    labels = config.category_labels
    for c in checks:
        name = cat_map.get(c.check_id, c.category)
        c.category = name
        c.category_label = labels.get(name, name)


def _has_scored(checks: List[CheckResult]) -> bool:
    """A category scores only when it holds a decided check with weight > 0. A
    category whose checks are all report-only (weight 0) has no real score: the
    unweighted fallback in ``_weighted_avg`` must never stand in for one."""
    return any(not c.skipped and c.weight > 0 for c in checks)


def _weighted_avg(checks: List[CheckResult]) -> float:
    scored = [c for c in checks if not c.skipped]
    total_w = sum(c.weight for c in scored)
    if total_w <= 0:
        return sum(c.score for c in scored) / len(scored) if scored else 0.0
    return sum(c.score * c.weight for c in scored) / total_w


def _apply_critical_penalties(
    checks: List[CheckResult], config: Config
) -> Tuple[float, List[CriticalPenalty]]:
    """Total penalty from FAILED critical checks + a CriticalPenalty per hit.

    A critical is an app-wide-exploitable defect (RCE / auth-bypass / injection):
    it must dominate rather than be averaged away, so it comes off the FINAL score.
    Each carries severity + repro (from config) plus the check's own live evidence
    so the deduction is defensible. A secret counts only through session_forgery:
    the live forgery with a public weak-key list is the critical itself."""
    crit = config.get("critical", {}) or {}
    penalties: Dict[str, float] = {
        str(k): float(v) for k, v in (crit.get("penalties", {}) or {}).items()
    }
    severity = crit.get("severity", {}) or {}
    repro = crit.get("repro", {}) or {}
    by_id = {c.check_id: c for c in checks}

    total = 0.0
    out: List[CriticalPenalty] = []
    for cid, pts in penalties.items():
        c = by_id.get(cid)
        if c is None or c.skipped or c.passed or c.unproven or pts <= 0:
            continue
        reasons = list(c.penalty_reasons)
        evidence = list(c.evidence)
        total += pts
        out.append(
            CriticalPenalty(
                check_id=cid, label=c.label, penalty=pts,
                severity=str(severity.get(cid, "")), repro=str(repro.get(cid, "")),
                reasons=reasons, evidence=evidence,
            )
        )
    return total, out


def combine_scores(
    check_results: List[CheckResult],
    config: Config,
    functional_failed: bool = False,
    boot_failed: bool = False,
) -> GradeResult:
    check_results = _dedupe_cve(check_results)
    _tag_owasp(check_results)
    _assign_categories(check_results, config)

    by_cat = defaultdict(list)
    for c in check_results:
        by_cat[c.category].append(c)

    cat_weights = config.category_weights  # normalized, sums to 1.0
    cat_labels = config.category_labels
    categories: List[CategoryResult] = []
    for name, checks in by_cat.items():
        categories.append(
            CategoryResult(
                name=name,
                score=_weighted_avg(checks),
                weight=float(cat_weights.get(name, 0.0)),
                checks=checks,
                label=cat_labels.get(name, name),
            )
        )

    # Renormalize over present categories so a static-only run scores on static alone.
    # A category whose checks were all skipped has no score, so it must not count.
    present_weight = sum(cat.weight for cat in categories if _has_scored(cat.checks))
    for cat in categories:
        share = cat.weight / present_weight if present_weight > 0 and _has_scored(cat.checks) else 0.0
        for c in cat.checks:
            c.category_weight = share
    if present_weight <= 0:
        # Nothing weighted was decided: no score to average. Report-only and
        # weight-0 categories must not turn into one.
        final = 0.0
    else:
        final = sum(
            cat.score * cat.weight for cat in categories if _has_scored(cat.checks)
        ) / present_weight

    raw_score = final

    # Critical defects come straight off the final score (before gate caps, which
    # are a ceiling — a critical can push it well below the cap).
    crit_total, critical_penalties = _apply_critical_penalties(check_results, config)
    if crit_total > 0:
        final = max(0.0, final - crit_total)

    capped = False
    cap_reason = ""
    if boot_failed:
        cap = float(config.get("gates.boot.fail_cap", 0))
        if final > cap:
            final = cap
            capped = True
            cap_reason = f"부팅 실패로 최종 점수 {cap} 상한 적용"
    elif functional_failed:
        cap = float(config.get("gates.functional.fail_cap", 40))
        if final > cap:
            final = cap
            capped = True
            cap_reason = f"기능 게이트 실패로 최종 점수 {cap} 상한 적용"

    return GradeResult(
        score=final,
        categories=categories,
        capped=capped,
        cap_reason=cap_reason,
        functional_failed=functional_failed,
        boot_failed=boot_failed,
        raw_score=raw_score,
        critical_penalties=critical_penalties,
    )
