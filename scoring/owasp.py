"""OWASP Top 10 (2025) tagging: maps each check_id to a category, tagged onto
each finding for reporting (never affects aggregation). Single source of truth."""
from __future__ import annotations

# check_id -> OWASP Top 10:2025 code
OWASP_BY_CHECK = {
    # A01 Broken Access Control (SSRF folded in for 2025)
    "idor_profile": "A01",
    "access_control_admin": "A01",
    "privilege_escalation": "A01",
    "csrf_protection": "A01",
    "ssrf_sink": "A01",
    # A02 Security Misconfiguration
    "debug_true": "A02",
    "security_headers": "A02",
    "transport_security": "A02",
    # A03 Software Supply Chain Failures (2021 "Vulnerable & Outdated Components")
    "cve": "A03",
    "typosquatting": "A03",
    "pypi_existence": "A03",
    # A04 Cryptographic Failures
    "hardcoded_secret": "A04",
    "weak_default_secret": "A04",
    "session_forgery": "A04",
    "password_hashing": "A04",
    "cookie_flags": "A04",
    "gitleaks": "A04",
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
    # A08 Software or Data Integrity Failures
    "insecure_deserialization": "A08",
    # A09 Security Logging and Alerting Failures
    "security_logging": "A09",
    # A10 Mishandling of Exceptional Conditions
    "verbose_errors": "A10",
    # General SAST — no single OWASP category.
    "semgrep": "",
}


def code_for(check_id: str) -> str:
    return OWASP_BY_CHECK.get(check_id, "")
