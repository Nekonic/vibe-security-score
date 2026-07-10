"""Scoring result dataclasses, each with ``.to_dict()`` for the web UI."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class CheckResult:
    check_id: str
    category: str  # rubric bucket id (assigned from config at aggregation time)
    label: str
    score: float  # 0..100
    weight: float
    passed: bool
    penalty_reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    # Skipped checks are excluded from aggregation (must not affect the score).
    skipped: bool = False
    tool: str = ""
    # OWASP Top 10 tag (e.g. "A01"); informational metadata, not aggregation.
    owasp: str = ""
    # Human label of the rubric category this check aggregates into (for UI).
    category_label: str = ""

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "category_label": self.category_label,
            "label": self.label,
            "score": round(float(self.score), 2),
            "weight": float(self.weight),
            "passed": bool(self.passed),
            "penalty_reasons": list(self.penalty_reasons),
            "evidence": list(self.evidence),
            "skipped": bool(self.skipped),
            "tool": self.tool,
            "owasp": self.owasp,
        }


@dataclass
class CategoryResult:
    name: str  # rubric bucket id
    score: float
    weight: float  # normalized category weight
    checks: List[CheckResult] = field(default_factory=list)
    label: str = ""  # human label for the bucket

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label or self.name,
            "score": round(float(self.score), 2),
            "weight": float(self.weight),
            "checks": [c.to_dict() for c in self.checks],
        }


@dataclass
class CriticalPenalty:
    """One app-wide-exploitable defect that subtracts from the FINAL score."""
    check_id: str
    label: str
    penalty: float
    severity: str = ""
    repro: str = ""
    reasons: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "penalty": round(float(self.penalty), 2),
            "severity": self.severity,
            "repro": self.repro,
            "reasons": list(self.reasons),
            "evidence": list(self.evidence),
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
    # Weighted category score BEFORE critical penalties (for transparency in UI).
    raw_score: float = 0.0
    critical_penalties: List[CriticalPenalty] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": round(float(self.score), 2),
            "raw_score": round(float(self.raw_score), 2),
            "grade": self.grade,
            "passed": bool(self.passed),
            "capped": bool(self.capped),
            "cap_reason": self.cap_reason,
            "functional_failed": bool(self.functional_failed),
            "boot_failed": bool(self.boot_failed),
            "critical_penalties": [p.to_dict() for p in self.critical_penalties],
            "categories": [c.to_dict() for c in self.categories],
        }
