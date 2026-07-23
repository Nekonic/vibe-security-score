"""A05 Injection (SQL): the SQL-parameterization static check and the SQLi probe.

The probe is authoritative-tool-first: in the default (non-dev) mode sqlmap decides,
and the built-in requests oracle runs only to corroborate a clean sqlmap result — it
is NOT a fallback for an absent tool (sqlmap that cannot run hard-fails; see
``dynamic_sqli``). Only ``--dev`` uses the oracle alone, with no external tool.
"""
from __future__ import annotations

import re
import uuid
from typing import Any, Dict, List, Optional

import requests

from ..models import CheckResult
from ..shared import sqlmap as sqlmap_tool
from ..shared.http import (
    DynamicContext, _body_text, _json_or_none, _looks_like_login_form, _scored_zero,
    _post_payload, _snip,
)
from ..shared.sources import _balanced_arg, _first_call_arg
from .base import Check, result


# ── sql_parameterization  (static) — execute()/executescript() with a string-
# built query.
_EXEC_CALL = re.compile(r"""\.\s*(execute|executescript)\s*\(""", re.IGNORECASE)


def check_sql_parameterization(check, sctx, cfg):
    penalty = float(cfg.get("penalty_per_raw_query", 40))
    score_ok = float(cfg.get("score_orm_or_parameterized", 100))

    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sctx.sources:
        for m in _EXEC_CALL.finditer(text):
            open_idx = text.index("(", m.end() - 1)
            arg = _balanced_arg(text, open_idx)
            lineno = text.count("\n", 0, m.start()) + 1
            # Only the query (first arg) can carry injection; bound params are safe.
            if _is_string_built_sql(_first_call_arg(arg)):
                reasons.append(f"{path}:{lineno} 문자열 조합 SQL을 execute()에 전달")
                evidence.append(f"{path}:{lineno}: {arg.strip()[:160]}")

    return result(check, cfg, score=score_ok - penalty * len(reasons),
                  passed=not reasons, reasons=reasons, evidence=evidence)


_STRUCTURAL_BEFORE = re.compile(r"""(order\s+by|group\s+by)\s*$""", re.IGNORECASE)


def _is_string_built_sql(arg: str) -> bool:
    """True when the execute() argument is a string assembled from an f-string,
    ``%`` formatting, ``+`` concatenation, or ``.format(...)``."""
    if re.search(r"""f['"]""", arg):
        # Flag only VALUE interpolation. Two interpolations are structural, not
        # injection, because they land where ``?`` binding is impossible:
        #   * ``{', '.join(cols)}`` — a column / ``SET a=?, b=?`` list (values still bound).
        #   * ``ORDER BY {expr}`` / ``GROUP BY {expr}`` — an identifier position; even the
        #     secure (whitelisted) sort MUST f-string it. Real ORDER BY injection is caught
        #     authoritatively by the dynamic ``/posts?sort=`` probe, so flagging it here would
        #     only false-positive on the safe whitelist pattern.
        # Any OTHER brace (e.g. f"... = '{q}'") is a value interpolation → risky.
        for m in re.finditer(r"\{([^{}]+)\}", arg):
            if ".join(" in m.group(1):
                continue
            if _STRUCTURAL_BEFORE.search(arg[:m.start()].rstrip()):
                continue
            return True
    if re.search(r"""['"][^'"]*['"]\s*\.\s*format\s*\(""", arg, re.DOTALL):
        return True
    if re.search(r"""['"][^'"]*['"]\s*%\s*[\(\w]""", arg, re.DOTALL):
        return True
    if re.search(r"""['"][^'"]*['"]\s*\+|\+\s*['"][^'"]*['"]""", arg, re.DOTALL):
        return True
    return False


# sqli (dynamic). Opts out of standard handling (standard=False in CHECKS): outside
# --dev this probe RAISES when sqlmap cannot run (see dynamic_sqli), and that hard-fail
# must PROPAGATE out of run_dynamic/grade_submission as an operational error. The runner
# wraps standard dynamic probes in try/except → it would swallow the raise into an
# _undecidable skip. So this probe keeps its own signature and its own _scored_zero handling.
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
    """SQLi verdict.

    Default (non-dev): sqlmap is authoritative. If it CANNOT run (disabled/missing/
    timeout/error) the dynamic phase FAILS HARD (raises) instead of silently
    degrading to the built-in oracle — outside ``--dev`` a verdict must come from the
    real tool. When sqlmap ran and found nothing, the built-in oracle still runs as
    corroboration (it catches auth-bypass/error-based cases the shallow scan misses).

    ``--dev`` (test level): no external tool — the built-in requests oracle alone.
    """
    weight = float(cfg.get("weight", 16))
    label = _SQLI_LABEL

    if ctx.dev:
        return _sqli_builtin_oracle(ctx, cfg, weight, label, "--dev: 내장 오라클 사용(sqlmap 미실행)")

    outcome = sqlmap_tool.run_sqlmap(ctx.base_url, ctx.sqlmap_cfg)
    if not outcome.ran:
        # No tool result and not in --dev: refuse to fabricate a verdict. grade_submission
        # lets this propagate as an operational failure (distinct from a boot failure).
        raise RuntimeError(
            f"sqlmap 실행 불가로 SQLi 판정 불가: {outcome.reason}. "
            "sqlmap 설치·활성화 후 재실행하거나, 내장 오라클(테스트 수준)로 돌리려면 --dev 를 사용하세요."
        )

    if outcome.injectable:
        ev = ["path=sqlmap (primary)"] + [_snip(e) for e in outcome.evidence]
        return CheckResult(
            check_id="sqli", category="dynamic", label=label,
            score=float(cfg.get("score_injection", 0)), weight=weight, passed=False,
            penalty_reasons=["sqlmap이 /search 또는 /posts 파라미터에서 SQL 인젝션 확인 → 매개변수 바인딩 미적용"],
            evidence=ev, tool="sqlmap",
        )

    # sqlmap ran clean → corroborate with the built-in oracle (never a fallback for
    # an absent tool; sqlmap already ran).
    return _sqli_builtin_oracle(ctx, cfg, weight, label, outcome.reason or "sqlmap 인젝션 미검출")


def _sqli_builtin_oracle(
    ctx: DynamicContext, cfg: Dict[str, Any], weight: float, label: str, note: str
) -> CheckResult:
    try:
        tool = "" if note.startswith("--dev:") else "sqlmap+requests"
        sess = ctx.userA.session if ctx.userA is not None else requests.Session()
        evidence: List[str] = [_snip(f"path=requests-oracle ({note})")]
        injection = False
        error_leak = False

        # (0) Auth-bypass SQLi: inject into /login; reaching an authenticated state
        # (no login form re-rendered) with a bogus password => injection.
        for pay in ctx.sqli_auth_bypass:
            r = ctx.post(requests.Session(), "/login", {"username": pay, "phone": pay, "password": "x"})
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
                evidence=evidence, tool=tool,
            )
        if error_leak:
            return CheckResult(
                check_id="sqli", category="dynamic", label=label,
                score=float(cfg.get("score_error_leak", 40)), weight=weight, passed=False,
                penalty_reasons=["완전한 인젝션은 아니나 SQL 오류/스택트레이스가 응답에 노출됨"],
                evidence=evidence, tool=tool,
            )
        return CheckResult(
            check_id="sqli", category="dynamic", label=label,
            score=float(cfg.get("score_no_injection", 100)), weight=weight, passed=True,
            penalty_reasons=[],
            evidence=evidence + [_snip("boolean 차등/오류 노출 모두 없음 → 인젝션 미발견")],
            tool=tool,
        )
    except Exception as exc:  # pragma: no cover
        return _scored_zero("sqli", label, weight, f"SQLi 프로브 예외: {exc}")


CHECKS = [
    Check("sql_parameterization", "SQL 파라미터화", "static",
          check_sql_parameterization),
    # standard=False: outside --dev this probe RAISES when sqlmap can't run, and that
    # hard-fail must propagate — the runner would otherwise wrap it into a skip.
    Check("sqli", _SQLI_LABEL, "dynamic", dynamic_sqli, standard=False),
]
