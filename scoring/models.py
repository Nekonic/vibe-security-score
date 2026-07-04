"""Scoring result dataclasses, each with ``.to_dict()`` for the web UI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class CheckResult:
    check_id: str
    category: str  # "static" | "dynamic"
    label: str
    score: float  # 0..100
    weight: float
    passed: bool
    penalty_reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    # Skipped checks are excluded from aggregation (must not affect the score).
    skipped: bool = False
    tool: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "label": self.label,
            "score": round(float(self.score), 2),
            "weight": float(self.weight),
            "passed": bool(self.passed),
            "penalty_reasons": list(self.penalty_reasons),
            "evidence": list(self.evidence),
            "skipped": bool(self.skipped),
            "tool": self.tool,
        }


@dataclass
class CategoryResult:
    name: str  # "static" | "dynamic"
    score: float
    weight: float  # normalized category weight
    checks: List[CheckResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "score": round(float(self.score), 2),
            "weight": float(self.weight),
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class GradeResult:
    score: float
    grade: str
    categories: List[CategoryResult] = field(default_factory=list)
    capped: bool = False
    cap_reason: str = ""
    passed: bool = False
    functional_failed: bool = False
    boot_failed: bool = False

    def to_dict(self) -> dict:
        return {
            "score": round(float(self.score), 2),
            "grade": self.grade,
            "passed": bool(self.passed),
            "capped": bool(self.capped),
            "cap_reason": self.cap_reason,
            "functional_failed": bool(self.functional_failed),
            "boot_failed": bool(self.boot_failed),
            "categories": [c.to_dict() for c in self.categories],
        }
