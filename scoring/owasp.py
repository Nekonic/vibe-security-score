"""OWASP Top 10 (2021) tagging: maps each check_id to a category, for reporting
and UI grouping only (never affects aggregation). Single source of the mapping."""
from __future__ import annotations

# check_id -> OWASP code
OWASP_BY_CHECK = {
    # A01 Broken Access Control
    "idor_profile": "A01",
    "access_control_admin": "A01",
    "csrf_protection": "A01",
    # A02 Cryptographic Failures
    "hardcoded_secret": "A02",
    "weak_default_secret": "A02",
    "session_forgery": "A02",
    "password_hashing": "A02",
    "cookie_flags": "A02",
    # A03 Injection
    "sql_parameterization": "A03",
    "xss_template": "A03",
    "csp": "A03",
    "sqli": "A03",
    "stored_xss": "A03",
    "reflected_xss": "A03",
    # A04 Insecure Design
    "rate_limiting": "A04",
    # A05 Security Misconfiguration
    "debug_true": "A05",
    "security_headers": "A05",
    "verbose_errors": "A05",
    "transport_security": "A05",
    # A06 Vulnerable and Outdated Components
    "cve": "A06",
    "typosquatting": "A06",
    # A07 Identification and Authentication Failures
    "functional": "A07",
    "weak_password_policy": "A07",
    # A08 Software and Data Integrity Failures
    "insecure_deserialization": "A08",
    # A09 Security Logging and Monitoring Failures
    "security_logging": "A09",
    # A10 Server-Side Request Forgery
    "ssrf_sink": "A10",
    # Auxiliary / participant lever (not an OWASP control)
    "prompt_intent": "",
    "gitleaks": "A02",
    "semgrep": "",
    "pypi_existence": "A06",
}

OWASP_LABELS = {
    "A01": "A01: 접근 통제 실패",
    "A02": "A02: 암호화 실패",
    "A03": "A03: 인젝션",
    "A04": "A04: 안전하지 않은 설계",
    "A05": "A05: 보안 설정 오류",
    "A06": "A06: 취약하고 오래된 구성요소",
    "A07": "A07: 식별 및 인증 실패",
    "A08": "A08: 소프트웨어 및 데이터 무결성 실패",
    "A09": "A09: 보안 로깅 및 모니터링 실패",
    "A10": "A10: 서버측 요청 위조(SSRF)",
    "": "기타",
}


def code_for(check_id: str) -> str:
    return OWASP_BY_CHECK.get(check_id, "")


def label_for(code: str) -> str:
    return OWASP_LABELS.get(code, "기타")
