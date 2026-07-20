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
    so the deduction is defensible. session_forgery, when it live-confirms, is
    folded into weak_default_secret's evidence (no separate/double penalty)."""
    crit = config.get("critical", {}) or {}
    penalties: Dict[str, float] = {
        str(k): float(v) for k, v in (crit.get("penalties", {}) or {}).items()
    }
    severity = crit.get("severity", {}) or {}
    repro = crit.get("repro", {}) or {}
    by_id = {c.check_id: c for c in checks}

    sf = by_id.get("session_forgery")
    sf_confirmed = sf is not None and not sf.skipped and not sf.passed

    total = 0.0
    out: List[CriticalPenalty] = []
    for cid, pts in penalties.items():
        c = by_id.get(cid)
        if c is None or c.skipped or c.passed or pts <= 0:
            continue
        # hardcoded_secret is critical ONLY when the live session-forgery PoC proves
        # the key is exploitable (forged an admin session). A hardcoded-but-not-
        # forgeable key stays a minor static finding — no critical.
        if cid == "hardcoded_secret" and not sf_confirmed:
            continue
        reasons = list(c.penalty_reasons)
        evidence = list(c.evidence)
        # Fold the live forge PoC into the secret finding that caused it.
        if cid in ("weak_default_secret", "hardcoded_secret") and sf_confirmed:
            reasons = reasons + list(sf.penalty_reasons)
            evidence = evidence + sf.evidence
        total += pts
        out.append(
            CriticalPenalty(
                check_id=cid, label=c.label, penalty=pts,
                severity=str(severity.get(cid, "")), repro=str(repro.get(cid, "")),
                reasons=reasons, evidence=evidence,
            )
        )
    return total, out


def _pass_threshold(config: Config) -> float:
    # Lowest passing score = smallest grade min > 0 (min-0 grade is the fail bucket).
    mins = [float(g.get("min", 0)) for g in (config.get("grades", []) or [])]
    positives = [m for m in mins if m > 0]
    return min(positives) if positives else 60.0


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
    present_weight = sum(cat.weight for cat in categories)
    if present_weight <= 0:
        final = (
            sum(cat.score for cat in categories) / len(categories)
            if categories else 0.0
        )
    else:
        final = sum(cat.score * cat.weight for cat in categories) / present_weight

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

    grade = config.grade_for(final)
    passed = (
        not boot_failed
        and not functional_failed
        and final >= _pass_threshold(config)
    )
    return GradeResult(
        score=final,
        grade=grade,
        categories=categories,
        capped=capped,
        cap_reason=cap_reason,
        passed=passed,
        functional_failed=functional_failed,
        boot_failed=boot_failed,
        raw_score=raw_score,
        critical_penalties=critical_penalties,
    )
