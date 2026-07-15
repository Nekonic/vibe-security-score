"""A05 Injection (SQL): the SQL-parameterization static check and the SQLi probe
(sqlmap primary when dev-enabled, built-in oracle fallback).
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional, Sequence

import requests

from ..models import CheckResult
from ..shared import sqlmap as sqlmap_tool
from ..shared.http import (
    DynamicContext, _body_text, _json_or_none, _looks_like_login_form, _scored_zero,
    _post_payload, _snip,
)
from ..shared.sources import Source, _balanced_arg, _clamp, _first_call_arg
from .base import Check


# sql_parameterization — execute()/executescript() with a string-built query.
_EXEC_CALL = re.compile(r"""\.\s*(execute|executescript)\s*\(""", re.IGNORECASE)


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


# sqli (dynamic)
def _row_count(resp: Optional[requests.Response]) -> Optional[int]:
    """Best-effort count of returned rows from JSON."""
    j = _json_or_none(resp)
    if isinstance(j, list):
        return len(j)
    if isinstance(j, dict):
        for key in ("results", "posts", "users", "data", "rows"):
            if isinstance(j.get(key), list):
                return len(j[key])
    return None


_SQL_ERROR_SIGNS = (
    "sqlite3", "operationalerror", "no such column", "syntax error",
    "sql error", "unrecognized token", "programmingerror", "psycopg2",
    "you have an error in your sql", "traceback (most recent call last)",
)


def _has_sql_error(resp: Optional[requests.Response]) -> bool:
    # A bare HTTP 500 is NOT proof of a SQL error/stacktrace leak — a hardened app
    # returns a generic 500 with no detail. Require an actual SQL/trace signature in
    # the body (matches A10 verbose_errors), so a clean 500 isn't a false positive.
    if resp is None:
        return False
    low = _body_text(resp).lower()
    return any(sign in low for sign in _SQL_ERROR_SIGNS)


_SQLI_LABEL = "SQL 인젝션(/search, /posts sort)"


def dynamic_sqli(ctx: DynamicContext, cfg: Dict[str, Any]) -> CheckResult:
    """SQLi verdict: sqlmap PRIMARY (if enabled+installed), built-in oracle FALLBACK."""
    weight = float(cfg.get("weight", 16))
    label = _SQLI_LABEL

    if ctx.dev:
        # --dev: use the built-in oracle instead of the external sqlmap CLI.
        outcome = sqlmap_tool.SqlmapOutcome(ran=False, reason="--dev: 내장 오라클 사용(sqlmap 미실행)")
    else:
        try:
            outcome = sqlmap_tool.run_sqlmap(ctx.base_url, ctx.sqlmap_cfg)
        except Exception as exc:  # any surprise => fall back
            outcome = sqlmap_tool.SqlmapOutcome(ran=False, reason=f"sqlmap 래퍼 예외({exc}) → 폴백")

    if outcome.ran and outcome.injectable:
        ev = ["path=sqlmap (primary)"] + [_snip(e) for e in outcome.evidence]
        return CheckResult(
            check_id="sqli", category="dynamic", label=label,
            score=float(cfg.get("score_injection", 0)), weight=weight, passed=False,
            penalty_reasons=["sqlmap이 /search 또는 /posts 파라미터에서 SQL 인젝션 확인 → 매개변수 바인딩 미적용"],
            evidence=ev, tool="sqlmap",
        )

    fallback_note = outcome.reason or "내장 오라클 사용"
    return _sqli_builtin_oracle(ctx, cfg, weight, label, fallback_note)


def _sqli_builtin_oracle(
    ctx: DynamicContext, cfg: Dict[str, Any], weight: float, label: str, fallback_note: str
) -> CheckResult:
    try:
        sess = ctx.userA.session if ctx.userA is not None else requests.Session()
        evidence: List[str] = [_snip(f"path=requests-oracle (fallback: {fallback_note})")]
        injection = False
        error_leak = False

        # (0) Auth-bypass SQLi: inject into /login; reaching an authenticated state
        # (no login form re-rendered) with a bogus password => injection.
        for pay in ctx.sqli_auth_bypass:
            r = ctx.post(requests.Session(), "/login", {"username": pay, "email": pay, "password": "x"})
            if r is not None and 200 <= r.status_code < 400 and not _looks_like_login_form(_body_text(r)):
                injection = True
                evidence.append(_snip(f"/login 인증우회 SQLi payload={pay!r} → 로그인 성공 상태 도달"))
                break

        # (1) Boolean differential on /search?q= — marker-count based so it works for
        # HTML-rendering apps (JSON row-count as corroboration).
        marker = uuid.uuid4().hex[:12]
        if ctx.userA is not None:
            ctx.post(sess, "/posts", _post_payload(f"sqli-seed-{marker}", f"seed-{marker}"))

        benign = ctx.get(sess, "/search", params={"q": f"nomatch-{uuid.uuid4().hex}"})
        benign_body = _body_text(benign)
        benign_hits = benign_body.count(marker)
        benign_n = _row_count(benign)
        inj = ctx.get(sess, "/search", params={"q": "%' OR '1'='1"})
        inj_body = _body_text(inj)
        inj_hits = inj_body.count(marker)
        inj_n = _row_count(inj)

        if not injection and inj_hits > benign_hits and inj_hits > 0:
            injection = True
            evidence.append(_snip(f"/search boolean 차등(HTML 마커): benign={benign_hits} vs \"OR 1=1\"={inj_hits} → SQLi"))
        if not injection and benign_n is not None and inj_n is not None and inj_n > benign_n and inj_n > 0:
            injection = True
            evidence.append(_snip(f"/search boolean 차등(JSON): benign={benign_n} rows vs \"OR 1=1\"={inj_n} rows → SQLi"))

        if not injection:
            for pay in ctx.sqli_payloads:
                r = ctx.get(sess, "/search", params={"q": pay})
                rb = _body_text(r)
                n = _row_count(r)
                if rb.count(marker) > benign_hits:
                    injection = True
                    evidence.append(_snip(f"/search payload {pay!r} → 마커 {rb.count(marker)}건(>{benign_hits}) → SQLi"))
                    break
                if n is not None and benign_n is not None and n > benign_n and n > 0:
                    injection = True
                    evidence.append(_snip(f"/search payload {pay!r} → {n} rows(>{benign_n}) → SQLi"))
                    break
                if _has_sql_error(r):
                    error_leak = True
                    evidence.append(_snip(f"/search payload {pay!r} → SQL 오류 노출: {rb}"))

        # Error-based on /posts?sort= (nonexistent column)
        bad_sort = ctx.get(sess, "/posts", params={"sort": "no_such_col_" + uuid.uuid4().hex[:6]})
        if _has_sql_error(bad_sort):
            error_leak = True
            evidence.append(_snip(f"/posts?sort=<bad col> → HTTP {bad_sort.status_code if bad_sort else 'n/a'} / SQL 오류"))
        # Comment-injected sort returning 200 while a bad column 500s => raw interpolation.
        inj_sort = ctx.get(sess, "/posts", params={"sort": "id-- "})
        if inj_sort is not None and bad_sort is not None:
            if inj_sort.status_code == 200 and bad_sort.status_code == 500:
                injection = True
                evidence.append(_snip("/posts?sort= 원본 문자열 보간 확인(주석 주입 200 / 잘못된 컬럼 500) → SQLi"))

        if injection:
            return CheckResult(
                check_id="sqli", category="dynamic", label=label,
                score=float(cfg.get("score_injection", 0)), weight=weight, passed=False,
                penalty_reasons=["/search 또는 /posts?sort= 에서 SQL 인젝션 성공 → 매개변수 바인딩 미적용"],
                evidence=evidence,
            )
        if error_leak:
            return CheckResult(
                check_id="sqli", category="dynamic", label=label,
                score=float(cfg.get("score_error_leak", 40)), weight=weight, passed=False,
                penalty_reasons=["완전한 인젝션은 아니나 SQL 오류/스택트레이스가 응답에 노출됨"],
                evidence=evidence,
            )
        return CheckResult(
            check_id="sqli", category="dynamic", label=label,
            score=float(cfg.get("score_no_injection", 100)), weight=weight, passed=True,
            penalty_reasons=[], evidence=[_snip("boolean 차등/오류 노출 모두 없음 → 인젝션 미발견")],
        )
    except Exception as exc:  # pragma: no cover
        return _scored_zero("sqli", label, weight, f"SQLi 프로브 예외: {exc}")


CHECKS = [
    Check("sql_parameterization", "SQL 파라미터화", "static",
            lambda sctx, cfg: check_sql_parameterization(sctx.sources, cfg)),
    Check("sqli", _SQLI_LABEL, "dynamic", dynamic_sqli),
]
