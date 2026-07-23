"""Scoring result dataclasses (each with ``.to_dict()`` for the web UI) and the
OWASP Top 10:2025 tag map. Leaf module — imports nothing from ``scoring``."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


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


# OWASP Top 10:2025 tagging. ``check_id`` -> family code, stamped onto each
# finding for reporting only (never affects aggregation). Single source of truth.
OWASP_BY_CHECK: Dict[str, str] = {
    # A01 Broken Access Control (SSRF folded in for 2025)
    "idor_profile": "A01",
    "access_control_admin": "A01",
    "privilege_escalation": "A01",
    "object_authorization": "A01",
    "admin_user_mgmt": "A01",
    "csrf_protection": "A01",
    "ssrf_sink": "A01",
    "ssrf": "A01",
    "comment_authorization": "A01",
    # A02 Security Misconfiguration
    "debug_true": "A02",
    "security_headers": "A02",
    "transport_security": "A02",
    # A03 Software Supply Chain Failures
    "cve": "A03",
    "typosquatting": "A03",
    "hallucinated_package": "A03",
    # A04 Cryptographic Failures
    "hardcoded_secret": "A04",
    "weak_default_secret": "A04",
    "session_forgery": "A04",
    "password_hashing": "A04",
    "cookie_flags": "A04",
    "gitleaks_secrets": "A04",
    # A05 Injection
    "sql_parameterization": "A05",
    "xss_template": "A05",
    "csp": "A05",
    "sqli": "A05",
    "stored_xss": "A05",
    "reflected_xss": "A05",
    # A06 Insecure Design
    "rate_limiting": "A06",
    # A07 Authentication Failures
    "functional": "A07",
    "weak_password_policy": "A07",
    "auth_session_management": "A07",
    # A08 Software or Data Integrity Failures
    "insecure_deserialization": "A08",
    "unrestricted_upload": "A08",
    # A09 Security Logging and Alerting Failures
    "security_logging": "A09",
    # A10 Mishandling of Exceptional Conditions
    "verbose_errors": "A10",
    # General SAST — no single OWASP category.
    "semgrep": "",
}


def code_for(check_id: str) -> str:
    """Return the OWASP family code for ``check_id`` (``""`` if untagged)."""
    return OWASP_BY_CHECK.get(check_id, "")
