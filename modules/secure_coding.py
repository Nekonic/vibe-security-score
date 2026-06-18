"""secure_coding.py — deterministic static-analysis module.

Exposes:
    analyze(code_dir: str) -> {"score": float, "findings": list[Finding]}

Uses only stdlib. All penalty values and constant lists come from config.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Import config from the project root, even when the module is imported
# from within the modules/ sub-package.
# ---------------------------------------------------------------------------
_here = Path(__file__).resolve().parent
_root = _here.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

import config  # noqa: E402  (after path fix)

# ===========================================================================
# Regex patterns — compiled once at module load.
# ===========================================================================

# 1. hardcoded_secret
#    FAIL: secret_key / SECRET_KEY / app.config[...] assigned a plain string literal.
#    PASS: value comes from os.environ / os.getenv / os.urandom / secrets.*
_RE_SECRET_ASSIGN = re.compile(
    r"""
    (?:
        # bare attribute: app.secret_key = '...'  /  secret_key = '...'
        (?:[\w.]+\.)?[Ss][Ee][Cc][Rr][Ee][Tt][_]?[Kk][Ee][Yy]
        \s*=\s*
        (?P<bare_val>['"]\S[^'"]{0,200}['"])
    |
        # dict key: app.config['SECRET_KEY'] = '...'  /  config['SECRET_KEY']='...'
        (?:[\w.]+)?\[['"]SECRET_KEY['"]\]
        \s*=\s*
        (?P<dict_val>['"]\S[^'"]{0,200}['"])
    )
    """,
    re.VERBOSE,
)
# Safe patterns on the same assignment line
_RE_SECRET_SAFE = re.compile(
    r"os\.environ|os\.getenv|os\.urandom|secrets\."
)

# 2. debug_true
_RE_DEBUG_TRUE = re.compile(
    r"""
    (?:
        app\.run\s*\([^)]*\bdebug\s*=\s*True   # app.run(debug=True ...)
    |
        ^\s*DEBUG\s*=\s*True                     # DEBUG = True (module level)
    |
        app\.debug\s*=\s*True                    # app.debug = True
    )
    """,
    re.VERBOSE | re.MULTILINE,
)

# 3. no_csrf — presence of any of these means PASS
_RE_CSRF_PRESENT = re.compile(
    r"""
    CSRFProtect               # Flask-SeaSurf / flask_wtf
    | flask_wtf
    | csrf_token              # template macro {{ csrf_token() }}
    | SeaSurf
    | @csrf
    | X-CSRF
    """,
    re.VERBOSE,
)

# 4. weak / strong password hashes
# STRONG: any of config.STRONG_PASSWORD_HASHES
_RE_STRONG_HASH = re.compile(
    r"|".join(re.escape(s) for s in config.STRONG_PASSWORD_HASHES)
)
# WEAK: any of config.WEAK_PASSWORD_HASHES
_RE_WEAK_HASH = re.compile(
    r"|".join(re.escape(s) for s in config.WEAK_PASSWORD_HASHES)
)

# 5. raw_sql
#    FAIL: cursor/execute/executemany called with f-string, + concat, % format,
#          or .format( containing SQL keywords.
#    PASS: parameterised query (?, %s with tuple), or no SQL.
_RE_RAW_SQL = re.compile(
    r"""
    (?:cursor|conn|db)\s*\.\s*execute(?:many)?\s*\(
    \s*
    (?:
        f['"]                         # f-string
    |
        [^)]*(?:SELECT|INSERT|UPDATE|DELETE)[^)]*
        (?:
            \s*\+\s*                  # + concatenation
        |
            \s*%\s*(?!\s*[\(%s])      # % formatting (not %s placeholder)
        |
            \.format\s*\(             # .format(
        )
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Stricter: look for execute( with f-string as first arg
_RE_EXECUTE_FSTRING = re.compile(
    r"""
    (?:cursor|conn|db)\s*\.\s*execute(?:many)?\s*\(\s*f['"]
    """,
    re.VERBOSE | re.IGNORECASE,
)

# execute( with string + variable concatenation
_RE_EXECUTE_CONCAT = re.compile(
    r"""
    (?:cursor|conn|db)\s*\.\s*execute(?:many)?\s*\(
    \s*
    (?:
        ['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)[^'"]*['"]\s*\+   # "SQL..." + var
    |
        [^'"(]+\s*\+\s*['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)   # var + "SQL..."
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# execute( with %-format: "SQL %s" % value  (not parameterised tuple)
_RE_EXECUTE_PERCENT = re.compile(
    r"""
    (?:cursor|conn|db)\s*\.\s*execute(?:many)?\s*\(
    [^)]*
    (?:SELECT|INSERT|UPDATE|DELETE)
    [^)]*
    %
    \s*
    (?!                 # negative look-ahead: NOT a parameterised call
        \s*[\(%s\[]    # ( starts a tuple/list, [ starts a list, %s is a placeholder
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# execute( where the SQL string contains .format(
_RE_EXECUTE_FORMAT = re.compile(
    r"""
    (?:cursor|conn|db)\s*\.\s*execute(?:many)?\s*\(
    [^)]*
    (?:SELECT|INSERT|UPDATE|DELETE)
    [^)]*
    \.format\s*\(
    """,
    re.VERBOSE | re.IGNORECASE,
)

# 6. xss checks (applied to Python files AND template files)
_RE_SAFE_FILTER = re.compile(r"\|\s*safe")           # |safe in templates
_RE_AUTOESCAPE_FALSE_PY = re.compile(
    r"autoescape\s*=\s*False", re.IGNORECASE
)
_RE_AUTOESCAPE_FALSE_TPL = re.compile(
    r"\{%-?\s*autoescape\s+false\s*-?%\}", re.IGNORECASE
)
_RE_MARKUP = re.compile(r"\bMarkup\s*\(")
# render_template_string with f-string template
_RE_RTS_FSTRING = re.compile(
    r"render_template_string\s*\(\s*f['\"]"
)
# render_template_string with variable (not a plain string literal)
# i.e. the first arg is NOT a simple str literal: render_template_string(var, ...)
# We allow render_template_string('...pure literal...') with NO extra args that are variables,
# but the spec says "fed any f-string/variable" = FAIL.
# Pattern: render_template_string( followed by something that's NOT a string literal
_RE_RTS_VAR = re.compile(
    r"render_template_string\s*\(\s*(?!['\"])"
)
# render_template_string('<literal>', keyword=variable_expr)
# The insecure_app line 55: render_template_string('<p>{{ error }}</p>', error=request.args...)
# This is a literal template BUT with external data injected via keyword — FAIL per spec.
_RE_RTS_WITH_KWARGS = re.compile(
    r"render_template_string\s*\(['\"][^'\"]*['\"],\s*\w+\s*="
)

# 7. insecure_session_cookie
# Both SESSION_COOKIE_SECURE=True and SESSION_COOKIE_SAMESITE='Lax'|'Strict' must be present.
_RE_SESS_SECURE = re.compile(
    r"SESSION_COOKIE_SECURE\s*=\s*True"
)
_RE_SESS_SAMESITE = re.compile(
    r"SESSION_COOKIE_SAMESITE\s*=\s*['\"](?:Lax|Strict)['\"]"
)

# 8. missing_security_headers — look for each header string in source
_RE_HEADERS = {
    h: re.compile(re.escape(h), re.IGNORECASE)
    for h in config.EXPECTED_SECURITY_HEADERS
}


# ===========================================================================
# File collection helpers
# ===========================================================================

def _collect_files(code_dir: str) -> tuple[list[Path], list[Path]]:
    """Return (py_files, template_files) under code_dir."""
    py_files: list[Path] = []
    tpl_files: list[Path] = []
    root = Path(code_dir)
    for dirpath, _dirs, filenames in os.walk(root):
        for fname in filenames:
            fp = Path(dirpath) / fname
            ext = fp.suffix.lower()
            if ext == ".py":
                py_files.append(fp)
            elif ext in (".html", ".jinja", ".j2"):
                tpl_files.append(fp)
    return py_files, tpl_files


def _read_safe(path: Path) -> str:
    """Read a file, replacing undecodable bytes. Returns '' on any error."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _concat(files: list[Path]) -> str:
    return "\n".join(_read_safe(f) for f in files)


# ===========================================================================
# Individual check functions
# ===========================================================================

def _check_hardcoded_secret(py_src: str) -> tuple[bool, str | None]:
    """Return (passed, evidence)."""
    for match in _RE_SECRET_ASSIGN.finditer(py_src):
        line_start = py_src.rfind("\n", 0, match.start()) + 1
        line_end = py_src.find("\n", match.end())
        if line_end == -1:
            line_end = len(py_src)
        line = py_src[line_start:line_end].strip()
        if not _RE_SECRET_SAFE.search(line):
            return False, line[:120]
    return True, None


def _check_debug_true(py_src: str) -> tuple[bool, str | None]:
    m = _RE_DEBUG_TRUE.search(py_src)
    if m:
        return False, m.group(0).strip()[:120]
    return True, None


def _check_no_csrf(all_src: str) -> tuple[bool, str | None]:
    """PASS if any CSRF construct found."""
    m = _RE_CSRF_PRESENT.search(all_src)
    if m:
        return True, None
    return False, "CSRF 관련 키워드 없음"


def _check_weak_password_hash(py_src: str) -> tuple[bool, str | None]:
    if _RE_STRONG_HASH.search(py_src):
        return True, None
    m = _RE_WEAK_HASH.search(py_src)
    if m:
        return False, f"약한 해시 사용: {m.group(0)}"
    return False, "해싱 미탐지/평문 의심"


def _check_raw_sql(py_src: str) -> tuple[bool, str | None]:
    """FAIL if SQL built via f-string / concat / % / .format passed to execute."""
    # Check f-string
    m = _RE_EXECUTE_FSTRING.search(py_src)
    if m:
        return False, m.group(0).strip()[:120]
    # Check concat (+ operator)
    m = _RE_EXECUTE_CONCAT.search(py_src)
    if m:
        return False, m.group(0).strip()[:120]
    # Check .format(
    m = _RE_EXECUTE_FORMAT.search(py_src)
    if m:
        return False, m.group(0).strip()[:120]
    # Check % formatting (not parameterised)
    m = _RE_EXECUTE_PERCENT.search(py_src)
    if m:
        return False, m.group(0).strip()[:120]
    return True, None


def _check_xss(py_src: str, tpl_src: str) -> tuple[bool, str | None]:
    """FAIL if |safe, render_template_string(variable/f-string), autoescape=False, Markup(."""
    # |safe in templates
    m = _RE_SAFE_FILTER.search(tpl_src)
    if m:
        return False, f"|safe 필터 발견: {m.group(0)}"
    # autoescape=False in Python
    m = _RE_AUTOESCAPE_FALSE_PY.search(py_src)
    if m:
        return False, m.group(0).strip()
    # {% autoescape false %} in templates
    m = _RE_AUTOESCAPE_FALSE_TPL.search(tpl_src)
    if m:
        return False, m.group(0).strip()
    # Markup( in Python
    m = _RE_MARKUP.search(py_src)
    if m:
        return False, m.group(0).strip()
    # render_template_string with f-string template
    m = _RE_RTS_FSTRING.search(py_src)
    if m:
        return False, m.group(0).strip()[:120]
    # render_template_string with non-literal first arg (variable)
    m = _RE_RTS_VAR.search(py_src)
    if m:
        return False, m.group(0).strip()[:120]
    # render_template_string('<literal>', keyword=something) — injects external data
    m = _RE_RTS_WITH_KWARGS.search(py_src)
    if m:
        return False, m.group(0).strip()[:120]
    return True, None


def _check_insecure_session_cookie(py_src: str) -> tuple[bool, str | None]:
    has_secure = bool(_RE_SESS_SECURE.search(py_src))
    has_samesite = bool(_RE_SESS_SAMESITE.search(py_src))
    if has_secure and has_samesite:
        return True, None
    missing = []
    if not has_secure:
        missing.append("SESSION_COOKIE_SECURE=True")
    if not has_samesite:
        missing.append("SESSION_COOKIE_SAMESITE='Lax'/'Strict'")
    return False, f"누락: {', '.join(missing)}"


def _check_missing_security_headers(all_src: str) -> tuple[bool, str | None]:
    present = [h for h, pat in _RE_HEADERS.items() if pat.search(all_src)]
    missing = [h for h in config.EXPECTED_SECURITY_HEADERS if h not in present]
    if len(present) >= config.SECURITY_HEADERS_MIN_PRESENT:
        return True, None
    return False, f"누락된 헤더: {', '.join(missing)}"


# ===========================================================================
# Finding builder
# ===========================================================================

_CHECK_LABELS = {
    "hardcoded_secret": "Hardcoded secret key",
    "debug_true": "Debug mode enabled",
    "no_csrf": "CSRF 보호 없음",
    "weak_password_hash": "약한 패스워드 해싱",
    "raw_sql": "Raw SQL (SQL Injection 위험)",
    "xss": "XSS 취약점",
    "insecure_session_cookie": "안전하지 않은 세션 쿠키",
    "missing_security_headers": "보안 헤더 누락",
}

_CHECK_REASONS_PASS = {
    "hardcoded_secret": (
        "SECRET_KEY가 환경 변수 또는 os.urandom에서 안전하게 로드됩니다. "
        "비밀 값을 소스 코드에 하드코딩하지 않는 것이 중요합니다."
    ),
    "debug_true": (
        "DEBUG 모드가 비활성화되어 있어 프로덕션 환경에서 스택 트레이스 및 "
        "내부 정보 노출 위험이 없습니다."
    ),
    "no_csrf": (
        "CSRF 보호가 구현되어 있어 교차 사이트 요청 위조 공격을 방지합니다."
    ),
    "weak_password_hash": (
        "강력한 패스워드 해싱 알고리즘(bcrypt, argon2, generate_password_hash 등)이 "
        "사용되어 패스워드가 안전하게 저장됩니다."
    ),
    "raw_sql": (
        "파라미터화된 쿼리를 사용하여 SQL 인젝션 공격을 방지합니다. "
        "? 또는 %s 플레이스홀더와 튜플로 값을 전달하는 것이 올바른 방법입니다."
    ),
    "xss": (
        "|safe 필터, render_template_string에 사용자 입력 직접 삽입, "
        "autoescape 비활성화 등의 XSS 취약점이 발견되지 않았습니다."
    ),
    "insecure_session_cookie": (
        "SESSION_COOKIE_SECURE와 SESSION_COOKIE_SAMESITE가 올바르게 설정되어 "
        "세션 쿠키가 안전하게 전송됩니다."
    ),
    "missing_security_headers": (
        "필요한 보안 헤더(Content-Security-Policy, X-Frame-Options 등)가 "
        "설정되어 있어 다양한 클라이언트 측 공격을 방지합니다."
    ),
}

_CHECK_REASONS_FAIL = {
    "hardcoded_secret": (
        "SECRET_KEY가 소스 코드에 하드코딩되어 있습니다. "
        "비밀 값은 반드시 환경 변수(os.environ.get)나 시크릿 관리 서비스를 통해 로드해야 합니다. "
        "하드코딩된 시크릿은 소스 코드 유출 시 즉각적인 보안 침해로 이어집니다."
    ),
    "debug_true": (
        "DEBUG=True 또는 app.run(debug=True)가 설정되어 있습니다. "
        "프로덕션 환경에서 Debug 모드는 스택 트레이스, 내부 코드, 변수 값 등 "
        "민감한 정보를 외부에 노출시킬 수 있으며, Werkzeug 디버거를 통한 원격 코드 실행 위험도 있습니다."
    ),
    "no_csrf": (
        "CSRF(Cross-Site Request Forgery) 보호가 구현되어 있지 않습니다. "
        "Flask-WTF의 CSRFProtect나 csrf_token()을 사용하여 상태 변경 요청을 보호해야 합니다. "
        "CSRF 취약점은 공격자가 인증된 사용자를 대신하여 악의적인 요청을 보낼 수 있게 합니다."
    ),
    "weak_password_hash": (
        "MD5, SHA1 등 암호화에 취약한 해싱 알고리즘이 사용되거나 해싱이 감지되지 않았습니다. "
        "패스워드는 반드시 bcrypt, argon2, scrypt 등 패스워드 전용 해싱 알고리즘이나 "
        "werkzeug의 generate_password_hash를 사용하여 저장해야 합니다."
    ),
    "raw_sql": (
        "SQL 쿼리가 f-string, 문자열 연결(+), % 포맷팅 또는 .format()으로 동적 생성되어 "
        "SQL 인젝션 공격에 취약합니다. "
        "반드시 파라미터화된 쿼리(? 또는 %s 플레이스홀더)를 사용하거나 ORM을 활용하세요."
    ),
    "xss": (
        "XSS(Cross-Site Scripting) 취약점이 발견되었습니다. |safe 필터, "
        "render_template_string에 f-string이나 변수 직접 삽입, "
        "autoescape=False 설정, Markup() 사용은 사용자 입력이 그대로 HTML로 렌더링되어 "
        "스크립트 인젝션 공격을 허용할 수 있습니다."
    ),
    "insecure_session_cookie": (
        "SESSION_COOKIE_SECURE 또는 SESSION_COOKIE_SAMESITE가 설정되어 있지 않습니다. "
        "SESSION_COOKIE_SECURE=True는 HTTPS 연결에서만 쿠키를 전송하도록 하고, "
        "SESSION_COOKIE_SAMESITE='Lax' 또는 'Strict'는 CSRF 공격을 추가로 방어합니다."
    ),
    "missing_security_headers": (
        "필수 보안 헤더가 충분히 설정되어 있지 않습니다. "
        "Content-Security-Policy(XSS 방어), X-Frame-Options(클릭재킹 방어), "
        "X-Content-Type-Options(MIME 스니핑 방어) 등의 헤더를 after_request 훅으로 설정하세요."
    ),
}


def _make_finding(
    check_id: str,
    passed: bool,
    penalty: float,
    evidence: str | None,
) -> dict:
    reason = _CHECK_REASONS_PASS[check_id] if passed else _CHECK_REASONS_FAIL[check_id]
    if not passed and evidence and check_id == "weak_password_hash":
        # prepend the detected weak hash to the reason
        reason = f"{evidence}. " + reason
    return {
        "id": check_id,
        "label": _CHECK_LABELS[check_id],
        "passed": passed,
        "penalty": penalty,
        "reason": reason,
        "evidence": evidence,
    }


# ===========================================================================
# Public entry point
# ===========================================================================

def analyze(code_dir: str) -> dict:
    """Analyze code_dir for secure-coding issues.

    Returns {"score": float 0..100, "findings": list[Finding]}.
    """
    py_files, tpl_files = _collect_files(code_dir)

    py_src = _concat(py_files)
    tpl_src = _concat(tpl_files)
    all_src = py_src + "\n" + tpl_src

    penalties = config.SECURE_CODING_PENALTIES

    # Run all checks
    results: dict[str, tuple[bool, str | None]] = {
        "hardcoded_secret": _check_hardcoded_secret(py_src),
        "debug_true": _check_debug_true(py_src),
        "no_csrf": _check_no_csrf(all_src),
        "weak_password_hash": _check_weak_password_hash(py_src),
        "raw_sql": _check_raw_sql(py_src),
        "xss": _check_xss(py_src, tpl_src),
        "insecure_session_cookie": _check_insecure_session_cookie(py_src),
        "missing_security_headers": _check_missing_security_headers(all_src),
    }

    findings = []
    score = float(config.SECURE_CODING_START)

    for check_id, penalty_val in penalties.items():
        passed, evidence = results[check_id]
        deduction = 0.0 if passed else float(penalty_val)
        score -= deduction
        findings.append(_make_finding(check_id, passed, deduction, evidence))

    score = max(0.0, score)
    return {"score": score, "findings": findings}
