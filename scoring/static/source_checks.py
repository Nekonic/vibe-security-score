"""Source-level static checks (regex) over a participant Flask app.

Each function returns a CheckResult; all thresholds come from config/scoring.yaml.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Sequence, Tuple

from ..models import CheckResult

Source = Tuple[str, str]  # (relative_path, file_text)


def _iter_lines(sources: Sequence[Source]) -> Iterable[Tuple[str, int, str]]:
    for path, text in sources:
        for i, line in enumerate(text.splitlines(), start=1):
            yield path, i, line


def _clamp(score: float) -> float:
    return max(0.0, min(100.0, score))


# 1. hardcoded_secret — *_KEY / secret_key assigned a string literal.
# Handles NAME=, app.secret_key=, config['SECRET_KEY']=, app.config[...]=, NAME:.
_SECRET_LHS = re.compile(
    r"""
    (?P<lhs>
        (?:[A-Za-z_][\w.]*\.)?
        (?:
            (?:SECRET_KEY|secret_key)
          | (?:config\s*\[\s*['"]SECRET_KEY['"]\s*\])
          | (?:\[\s*['"]SECRET_KEY['"]\s*\])
        )
    )
    \s*[:=]\s*
    (?P<rhs>.+)$
    """,
    re.VERBOSE,
)
_ENV_REF = re.compile(
    r"""(os\.)?environ\s*(\[|\.get\s*\()|(os\.)?getenv\s*\(""",
    re.VERBOSE,
)
_STR_LITERAL = re.compile(r"""^\s*[a-zA-Z]?['"]""")


def check_hardcoded_secret(sources: Sequence[Source], cfg: dict) -> CheckResult:
    penalty = float(cfg.get("penalty_per_finding", 100))
    allow_env = bool(cfg.get("allow_env_reference", True))

    reasons: List[str] = []
    evidence: List[str] = []
    for path, lineno, line in _iter_lines(sources):
        m = _SECRET_LHS.search(line)
        if not m:
            continue
        rhs = m.group("rhs").strip()
        if allow_env and _ENV_REF.search(rhs):
            continue
        if not _STR_LITERAL.match(rhs):
            continue
        reasons.append(f"{path}:{lineno} SECRET_KEY 하드코딩")
        evidence.append(f"{path}:{lineno}: {line.strip()}")

    score = _clamp(100.0 - penalty * len(reasons))
    return CheckResult(
        check_id="hardcoded_secret",
        category="static",
        label="하드코딩 시크릿",
        score=score,
        weight=float(cfg.get("weight", 0)),
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
    )


# 2. debug_true
_DEBUG_TRUE = re.compile(
    r"""(debug\s*=\s*True)|(\bDEBUG\s*=\s*True\b)|(\[\s*['"]DEBUG['"]\s*\]\s*=\s*True)""",
    re.VERBOSE,
)


def check_debug_true(sources: Sequence[Source], cfg: dict) -> CheckResult:
    penalty = float(cfg.get("penalty_per_finding", 100))
    reasons: List[str] = []
    evidence: List[str] = []
    for path, lineno, line in _iter_lines(sources):
        if line.lstrip().startswith("#"):
            continue
        if _DEBUG_TRUE.search(line):
            reasons.append(f"{path}:{lineno} debug=True 사용")
            evidence.append(f"{path}:{lineno}: {line.strip()}")

    score = _clamp(100.0 - penalty * len(reasons))
    return CheckResult(
        check_id="debug_true",
        category="static",
        label="디버그 모드",
        score=score,
        weight=float(cfg.get("weight", 0)),
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
    )


# 3. password_hashing
_STRONG_HASH = re.compile(
    r"""bcrypt|argon2|scrypt|pbkdf2|generate_password_hash|check_password_hash|passlib""",
    re.IGNORECASE,
)
_WEAK_HASH = re.compile(r"""\b(md5|sha1)\s*\(""", re.IGNORECASE)
_PW_TOKEN = re.compile(r"""pass|pwd|\bpw\b|password|secret|credential""", re.IGNORECASE)
_PLAINTEXT_CMP = re.compile(
    r"""(?:pw|pwd|password|passwd)\s*==|==\s*(?:pw|pwd|password|passwd)\b""",
    re.IGNORECASE,
)


def check_password_hashing(sources: Sequence[Source], cfg: dict) -> CheckResult:
    score_strong = float(cfg.get("score_strong", 100))
    score_weak = float(cfg.get("score_weak_hash", 30))
    score_plain = float(cfg.get("score_plaintext", 0))
    score_unknown = float(cfg.get("score_unknown", 60))

    strong_ev: List[str] = []
    weak_ev: List[str] = []
    plain_ev: List[str] = []

    for path, lineno, line in _iter_lines(sources):
        if _STRONG_HASH.search(line):
            strong_ev.append(f"{path}:{lineno}: {line.strip()}")
        wm = _WEAK_HASH.search(line)
        if wm and _PW_TOKEN.search(line):
            weak_ev.append(f"{path}:{lineno}: {line.strip()}")
        if _PLAINTEXT_CMP.search(line):
            plain_ev.append(f"{path}:{lineno}: {line.strip()}")

    # Precedence: plaintext compare worst, then weak hash, then strong.
    if plain_ev:
        return CheckResult(
            "password_hashing", "static", "비밀번호 해싱",
            score_plain, float(cfg.get("weight", 0)),
            passed=False,
            penalty_reasons=[f"{e.split(':',2)[0]}:{e.split(':',2)[1]} 평문 비밀번호 비교"
                             for e in plain_ev],
            evidence=plain_ev,
        )
    if weak_ev:
        return CheckResult(
            "password_hashing", "static", "비밀번호 해싱",
            score_weak, float(cfg.get("weight", 0)),
            passed=False,
            penalty_reasons=[f"{e.split(':',2)[0]}:{e.split(':',2)[1]} 취약한 해시(md5/sha1) 사용"
                             for e in weak_ev],
            evidence=weak_ev,
        )
    if strong_ev:
        return CheckResult(
            "password_hashing", "static", "비밀번호 해싱",
            score_strong, float(cfg.get("weight", 0)),
            passed=True, penalty_reasons=[], evidence=strong_ev,
        )
    return CheckResult(
        "password_hashing", "static", "비밀번호 해싱",
        score_unknown, float(cfg.get("weight", 0)),
        passed=score_unknown >= 60,
        penalty_reasons=["명확한 비밀번호 해싱 로직을 찾지 못함"],
        evidence=[],
    )


# 4. sql_parameterization — execute()/executescript() with a string-built query.
_EXEC_CALL = re.compile(r"""\.\s*(execute|executescript)\s*\(""", re.IGNORECASE)


def _balanced_arg(text: str, open_idx: int) -> str:
    """Substring inside the parens starting at ``open_idx`` (the '(')."""
    depth = 0
    out = []
    for ch in text[open_idx:]:
        out.append(ch)
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
    return "".join(out)


def _first_call_arg(arg: str) -> str:
    """The first positional argument of a call whose balanced source (outer parens
    included) is ``arg``. For execute()/executescript() that is the SQL query
    itself — later args are *bound parameters* (e.g. an f-string LIKE value like
    ``f"%{q}%"``), which are safe and must NOT be mistaken for string-built SQL."""
    if not arg.startswith("("):
        return arg
    inner = arg[1:-1] if arg.endswith(")") else arg[1:]
    depth = 0
    i = 0
    n = len(inner)
    quote = None  # active string delimiter: ' " ''' or \"""
    while i < n:
        ch = inner[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if inner.startswith(quote, i):
                i += len(quote)
                quote = None
                continue
            i += 1
            continue
        if ch in "'\"":
            triple = inner[i:i + 3]
            if triple in ('"""', "'''"):
                quote = triple
                i += 3
                continue
            quote = ch
            i += 1
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return inner[:i]
        i += 1
    return inner


def check_sql_parameterization(sources: Sequence[Source], cfg: dict) -> CheckResult:
    penalty = float(cfg.get("penalty_per_raw_query", 40))
    score_ok = float(cfg.get("score_orm_or_parameterized", 100))

    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sources:
        for m in _EXEC_CALL.finditer(text):
            open_idx = text.index("(", m.end() - 1)
            arg = _balanced_arg(text, open_idx)
            lineno = text.count("\n", 0, m.start()) + 1
            # Only the query (first arg) can carry injection; bound params are safe.
            if _is_string_built_sql(_first_call_arg(arg)):
                reasons.append(f"{path}:{lineno} 문자열 조합 SQL을 execute()에 전달")
                evidence.append(f"{path}:{lineno}: {arg.strip()[:160]}")

    score = _clamp(score_ok - penalty * len(reasons))
    return CheckResult(
        check_id="sql_parameterization",
        category="static",
        label="SQL 파라미터화",
        score=score,
        weight=float(cfg.get("weight", 0)),
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
    )


def _is_string_built_sql(arg: str) -> bool:
    """True when the execute() argument is a string assembled from an f-string,
    ``%`` formatting, ``+`` concatenation, or ``.format(...)``."""
    if re.search(r"""f['"]""", arg):
        if re.search(r"""f['"][^'"]*\{[^}]+\}""", arg, re.DOTALL):
            return True
    if re.search(r"""['"][^'"]*['"]\s*\.\s*format\s*\(""", arg, re.DOTALL):
        return True
    if re.search(r"""['"][^'"]*['"]\s*%\s*[\(\w]""", arg, re.DOTALL):
        return True
    if re.search(r"""['"][^'"]*['"]\s*\+|\+\s*['"][^'"]*['"]""", arg, re.DOTALL):
        return True
    return False


# 5. xss_template
_RENDER_STR = re.compile(r"""render_template_string\s*\(""")
_SAFE_FILTER = re.compile(r"""\|\s*safe""")
_AUTOESCAPE_OFF = re.compile(r"""autoescape\s*=\s*False""", re.IGNORECASE)
_REQUEST_DATA = re.compile(r"""request\.|\bg\.|session\[""")
_TPL_SAFE = re.compile(r"""\{\{[^}]*\|\s*safe[^}]*\}\}""")
_TPL_AUTOESCAPE_OFF = re.compile(r"""\{%\s*autoescape\s+false\s*%\}""", re.IGNORECASE)


def check_xss_template(
    sources: Sequence[Source],
    cfg: dict,
    templates: Optional[Sequence[Source]] = None,
) -> CheckResult:
    penalty = float(cfg.get("penalty_per_finding", 35))
    score_clean = float(cfg.get("score_clean", 100))

    reasons: List[str] = []
    evidence: List[str] = []

    for path, text in sources:
        for m in _RENDER_STR.finditer(text):
            open_idx = text.index("(", m.end() - 1)
            arg = _balanced_arg(text, open_idx)
            lineno = text.count("\n", 0, m.start()) + 1
            if _REQUEST_DATA.search(arg) or _SAFE_FILTER.search(arg):
                reasons.append(f"{path}:{lineno} render_template_string에 사용자 입력/`|safe` 사용")
                evidence.append(f"{path}:{lineno}: {arg.strip()[:160]}")
        for i, line in enumerate(text.splitlines(), start=1):
            if _SAFE_FILTER.search(line) and _RENDER_STR.search(line) is None:
                if not any(f"{path}:{i}" in r for r in reasons):
                    reasons.append(f"{path}:{i} 템플릿 문자열에서 `|safe` 필터 사용")
                    evidence.append(f"{path}:{i}: {line.strip()}")
            if _AUTOESCAPE_OFF.search(line):
                reasons.append(f"{path}:{i} autoescape=False 설정")
                evidence.append(f"{path}:{i}: {line.strip()}")

    for path, text in (templates or []):
        for i, line in enumerate(text.splitlines(), start=1):
            if _TPL_SAFE.search(line):
                reasons.append(f"{path}:{i} |safe 필터로 자동 이스케이프 우회")
                evidence.append(f"{path}:{i}: {line.strip()}")
            if _TPL_AUTOESCAPE_OFF.search(line):
                reasons.append(f"{path}:{i} autoescape false 블록으로 이스케이프 비활성화")
                evidence.append(f"{path}:{i}: {line.strip()}")

    score = _clamp(score_clean - penalty * len(reasons))
    return CheckResult(
        check_id="xss_template",
        category="static",
        label="XSS 템플릿",
        score=score,
        weight=float(cfg.get("weight", 0)),
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
    )


# 8. prompt_intent — participant-controlled lever.
def _keyword_hit(keyword: str, haystack: str) -> bool:
    # ASCII alphanumeric keywords use word boundaries so e.g. "sqli" doesn't match
    # inside "sqlite"; Korean keywords have no boundaries, so plain substring.
    if keyword and all(ord(ch) < 128 for ch in keyword) and keyword[0].isalnum():
        return re.search(r"(?<![0-9a-z])" + re.escape(keyword) + r"(?![0-9a-z])", haystack) is not None
    return keyword in haystack


def check_prompt_intent(prompt_text: Optional[str], cfg: dict) -> CheckResult:
    baseline = float(cfg.get("score_baseline", 50))
    per_kw = float(cfg.get("score_per_keyword", 12))
    max_score = float(cfg.get("max_score", 100))
    keywords = list(cfg.get("security_keywords", []) or [])

    if prompt_text is None:
        return CheckResult(
            check_id="prompt_intent",
            category="static",
            label="프롬프트 보안 의도",
            score=baseline,
            weight=float(cfg.get("weight", 0)),
            passed=False,
            penalty_reasons=["prompt.md 없음"],
            evidence=[],
        )

    haystack = prompt_text.lower()
    hits = [kw for kw in keywords if _keyword_hit(str(kw).lower(), haystack)]
    distinct = list(dict.fromkeys(hits))
    score = min(max_score, baseline + len(distinct) * per_kw)
    passed = len(distinct) > 0
    reasons = [] if passed else ["프롬프트에 보안 요구사항 언급 없음"]
    return CheckResult(
        check_id="prompt_intent",
        category="static",
        label="프롬프트 보안 의도",
        score=score,
        weight=float(cfg.get("weight", 0)),
        passed=passed,
        penalty_reasons=reasons,
        evidence=distinct,
    )


# 6. cookie_flags
_COOKIE_FLAGS = {
    "SESSION_COOKIE_HTTPONLY": "HttpOnly",
    "SESSION_COOKIE_SECURE": "Secure",
    "SESSION_COOKIE_SAMESITE": "SameSite",
}


def check_cookie_flags(sources: Sequence[Source], cfg: dict) -> CheckResult:
    baseline = float(cfg.get("baseline", 25))
    per_flag = float(cfg.get("score_per_flag", 25))

    joined = "\n".join(text for _, text in sources)
    present = []
    evidence: List[str] = []
    for flag, label in _COOKIE_FLAGS.items():
        if re.search(re.escape(flag), joined):
            present.append(label)
            evidence.append(flag)

    score = _clamp(baseline + per_flag * len(present))
    missing = [lbl for lbl in _COOKIE_FLAGS.values() if lbl not in present]
    reasons = [f"세션 쿠키 {m} 플래그 미설정" for m in missing]
    return CheckResult(
        check_id="cookie_flags",
        category="static",
        label="쿠키 보안 플래그",
        score=score,
        weight=float(cfg.get("weight", 0)),
        passed=not missing,
        penalty_reasons=reasons,
        evidence=evidence,
    )


# 7. security_headers
_HEADERS = {
    "Content-Security-Policy": re.compile(r"""Content-Security-Policy|content_security_policy|['"]CSP['"]""", re.IGNORECASE),
    "X-Frame-Options": re.compile(r"""X-Frame-Options|frame_options""", re.IGNORECASE),
    "Strict-Transport-Security": re.compile(r"""Strict-Transport-Security|strict_transport_security|\bhsts\b""", re.IGNORECASE),
    "X-Content-Type-Options": re.compile(r"""X-Content-Type-Options|content_type_options""", re.IGNORECASE),
}
_HEADER_MECHANISM = re.compile(r"""after_request|Talisman""", re.IGNORECASE)


def check_security_headers(sources: Sequence[Source], cfg: dict) -> CheckResult:
    baseline = float(cfg.get("baseline", 20))
    per_header = float(cfg.get("score_per_header", 20))

    joined = "\n".join(text for _, text in sources)
    has_mechanism = bool(_HEADER_MECHANISM.search(joined))
    present = []
    evidence: List[str] = []
    talisman = bool(re.search(r"""Talisman""", joined))  # applies a strong default header set
    for name, pat in _HEADERS.items():
        if talisman or (pat.search(joined) and has_mechanism):
            present.append(name)
            evidence.append(name)

    score = _clamp(baseline + per_header * len(present))
    missing = [h for h in _HEADERS if h not in present]
    reasons = [f"{m} 보안 헤더 미설정" for m in missing]
    return CheckResult(
        check_id="security_headers",
        category="static",
        label="보안 헤더",
        score=score,
        weight=float(cfg.get("weight", 0)),
        passed=not missing,
        penalty_reasons=reasons,
        evidence=evidence,
    )
