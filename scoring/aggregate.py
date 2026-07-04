"""Combine per-check results into category scores and a final GradeResult."""
from __future__ import annotations

from collections import defaultdict
from typing import List

from .config import Config
from .models import CategoryResult, CheckResult, GradeResult


def _weighted_avg(checks: List[CheckResult]) -> float:
    scored = [c for c in checks if not c.skipped]
    total_w = sum(c.weight for c in scored)
    if total_w <= 0:
        return sum(c.score for c in scored) / len(scored) if scored else 0.0
    return sum(c.score * c.weight for c in scored) / total_w


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
    by_cat = defaultdict(list)
    for c in check_results:
        by_cat[c.category].append(c)

    cat_weights = config.category_weights  # normalized, sums to 1.0
    categories: List[CategoryResult] = []
    for name, checks in by_cat.items():
        categories.append(
            CategoryResult(
                name=name,
                score=_weighted_avg(checks),
                weight=float(cat_weights.get(name, 0.0)),
                checks=checks,
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
    )
