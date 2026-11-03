"""A05 Injection (SQL): the SQL-parameterization static check and the SQLi probe.

The probe is authoritative-tool-first: in the default (non-dev) mode sqlmap decides,
and the built-in requests oracle runs only to corroborate a clean sqlmap result — it
is NOT a fallback for an absent tool (sqlmap that cannot run hard-fails; see
``dynamic_sqli``). Only ``--dev`` uses the oracle alone, with no external tool.
"""
from __future__ import annotations

import ast
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
        consts = _ConstQuery.parse(text)
        for m in _EXEC_CALL.finditer(text):
            open_idx = text.index("(", m.end() - 1)
            arg = _balanced_arg(text, open_idx)
            lineno = text.count("\n", 0, m.start()) + 1
            # Only the query (first arg) can carry injection; bound params are safe.
            query = _first_call_arg(arg)
            if _is_string_built_sql(query, has_params=_has_params(arg, query)) \
                    and not (consts and consts.constant_query(text, m.end(1))):
                reasons.append(f"{path}:{lineno} 문자열 조합 SQL을 execute()에 전달")
                evidence.append(f"{path}:{lineno}: {arg.strip()[:160]}")

    return result(check, cfg, score=score_ok - penalty * len(reasons),
                  passed=not reasons, reasons=reasons, evidence=evidence)


_STRUCTURAL_BEFORE = re.compile(r"""(order\s+by|group\s+by)\s*$""", re.IGNORECASE)
# Names apps give to assembled SQL FRAGMENTS (a WHERE built from fixed `col = ?` pieces,
# a whitelisted sort, a column list). Only trusted when the values are bound
# separately (has_params) — the fragment then carries no user value.
_FRAGMENT_NAME = re.compile(
    r"""^(?:where|where_sql|where_clause|clause|clauses|cond|conds|condition|conditions|"""
    r"""filters?|order|order_by|orderby|sort|sort_sql|cols|columns|fields|placeholders|sets?|set_clause)$""",
    re.IGNORECASE)


def _has_params(call_args: str, query: str) -> bool:
    """execute(query, params): a second argument carries the bound values."""
    q = query.strip()
    idx = call_args.find(q)
    if not q or idx < 0:
        return False
    rest = call_args[idx + len(q):].strip().rstrip(")").strip()
    return rest.startswith(",") and bool(rest[1:].strip())


def _structural(expr: str, before: str, has_params: bool) -> bool:
    """A non-literal piece of the query that cannot carry an injected VALUE: an
    identifier after ORDER/GROUP BY, a column-list join, or a named SQL fragment
    whose values are bound separately."""
    expr = expr.strip()
    if ".join(" in expr or _STRUCTURAL_BEFORE.search(before.rstrip()):
        return True
    return has_params and bool(_FRAGMENT_NAME.match(expr))


def _concat_parts(arg: str) -> List[str]:
    """Split a query expression on top-level ``+`` (outside quotes/brackets)."""
    parts, buf, depth, quote = [], [], 0, ""
    for ch in arg:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0:
            parts.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    parts.append("".join(buf))
    return parts


_LITERAL = re.compile(r"""^\s*[rbu]?(['"])(.*)\1\s*$""", re.IGNORECASE | re.DOTALL)


def _is_string_built_sql(arg: str, has_params: bool = False) -> bool:
    """True when the execute() query is assembled with a user VALUE spliced in via an
    f-string, ``%`` formatting, ``+`` concatenation, or ``.format(...)``. Structural
    pieces (identifier after ORDER/GROUP BY, column lists, named fragments with bound
    params) are not injection points — even a whitelisted sort MUST be spliced, and
    real injection there is caught authoritatively by the dynamic ``/posts?sort=`` probe."""
    if re.search(r"""f['"]""", arg):
        for m in re.finditer(r"\{([^{}]+)\}", arg):
            if not _structural(m.group(1), arg[:m.start()], has_params):
                return True
    if re.search(r"""['"][^'"]*['"]\s*\.\s*format\s*\(""", arg, re.DOTALL):
        return True
    if re.search(r"""['"][^'"]*['"]\s*%\s*[\(\w]""", arg, re.DOTALL):
        return True
    parts = _concat_parts(arg)
    if len(parts) > 1:
        before = ""
        for part in parts:
            lit = _LITERAL.match(part)
            if lit:
                before += lit.group(2)
            elif not _structural(part, before, has_params):
                return True
            else:
                before += " ? "
    return False


class _Unpacked(ast.AST):
    """Element ``index`` of ``value``: ``clause, args = visible_clause()``."""
    _fields = ("value",)

    def __init__(self, value: ast.AST, index: int):
        super().__init__()
        self.value, self.index = value, index


def _unpacked(target, name: str, value: ast.AST) -> Optional[ast.AST]:
    """A flat tuple target binding ``name``: its element of ``value``, else None."""
    if isinstance(target, (ast.Tuple, ast.List)):
        for i, t in enumerate(target.elts):
            if isinstance(t, ast.Name) and t.id == name:
                return _Unpacked(value, i)
    return None


class _ConstQuery:
    """Second opinion on a query the text heuristics flag: proves with the AST that
    every piece of it comes from string literals. A base query kept in a variable and
    grown with fixed `+=` fragments, passed in from call sites that all pass literals,
    returned by a helper, or picked from a literal whitelist (a dict lookup, a
    conditional between literals) carries no user value. Anything it cannot resolve
    stays flagged."""

    _SAFE_METHODS = {"strip", "lstrip", "rstrip", "upper", "lower"}
    _FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef)

    def __init__(self, tree: ast.Module):
        self.tree = tree
        self.parent: Dict[ast.AST, ast.AST] = {}
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parent[child] = node
        self.funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, self._FUNCS)}

    @classmethod
    def parse(cls, text: str) -> Optional["_ConstQuery"]:
        try:
            return cls(ast.parse(text))
        except (SyntaxError, ValueError):
            return None

    def constant_query(self, text: str, attr_end: int) -> bool:
        """Whether the execute() call whose attribute name ends at char offset
        ``attr_end`` gets a query made only of literals."""
        line = text.count("\n", 0, attr_end) + 1
        col = len(text[text.rfind("\n", 0, attr_end) + 1:attr_end].encode("utf-8"))
        for node in ast.walk(self.tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.end_lineno == line and node.func.end_col_offset == col):
                return bool(node.args) and self._safe(node.args[0], self._scope(node), frozenset())
        return False

    def _scope(self, node: ast.AST) -> ast.AST:
        while node in self.parent:
            node = self.parent[node]
            if isinstance(node, self._FUNCS):
                return node
        return self.tree

    def _safe(self, node, scope, seen) -> bool:
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) or self._safe(v.value, scope, seen)
                       for v in node.values)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mult):  # "?," * len(ids)
                return self._safe(node.left, scope, seen) or self._safe(node.right, scope, seen)
            if isinstance(node.op, (ast.Add, ast.Mod)):
                return self._safe(node.left, scope, seen) and self._safe(node.right, scope, seen)
            return False
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return all(self._safe(e, scope, seen) for e in node.elts)
        if isinstance(node, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            return self._safe(node.elt, scope, seen)
        if isinstance(node, ast.Dict):
            return all(v is not None and self._safe(v, scope, seen) for v in node.values)
        if isinstance(node, ast.IfExp):
            return self._safe(node.body, scope, seen) and self._safe(node.orelse, scope, seen)
        if isinstance(node, ast.BoolOp):
            return all(self._safe(v, scope, seen) for v in node.values)
        if isinstance(node, ast.Subscript):  # {"title": "title ASC"}[key]
            return self._whitelist(node.value, scope, seen)
        if isinstance(node, ast.Call):
            return self._safe_call(node, scope, seen)
        if isinstance(node, ast.Name):
            return self._safe_name(node.id, scope, seen)
        if isinstance(node, _Unpacked):
            return self._safe_element(node, scope, seen)
        return False

    def _safe_element(self, node: "_Unpacked", scope, seen) -> bool:
        """A tuple literal's element, or that element of every tuple a local helper
        returns."""
        v, i = node.value, node.index

        def elements(expr) -> Optional[List[ast.AST]]:
            """Element ``i`` of each tuple ``expr`` can be (a conditional picks one)."""
            if isinstance(expr, (ast.Tuple, ast.List)):
                return [expr.elts[i]] if i < len(expr.elts) else None
            if isinstance(expr, ast.IfExp):
                a, b = elements(expr.body), elements(expr.orelse)
                return a + b if a is not None and b is not None else None
            return None

        if isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id in self.funcs:
            key = ("ret", v.func.id, i)
            if key in seen:
                return True
            fn = self.funcs[v.func.id]
            found = [elements(n.value) for n in ast.walk(fn) if isinstance(n, ast.Return)]
            return bool(found) and all(e is not None and all(self._safe(x, fn, seen | {key}) for x in e)
                                       for e in found)
        found = elements(v)
        return found is not None and all(self._safe(x, scope, seen) for x in found)

    def _whitelist(self, node, scope, seen) -> bool:
        """A dict whose values are all literals, inline or held in a name."""
        if isinstance(node, ast.Dict):
            return self._safe(node, scope, seen)
        if isinstance(node, ast.Name):
            values = self._assigned(node.id, scope)
            if values is None and scope is not self.tree:
                values = self._assigned(node.id, self.tree)
            return bool(values) and all(isinstance(v, ast.Dict) and self._safe(v, scope, seen)
                                        for v in values)
        return False

    def _safe_call(self, node: ast.Call, scope, seen) -> bool:
        f = node.func
        if isinstance(f, ast.Attribute):
            if f.attr == "get" and node.args:  # whitelist.get(key, default)
                return (self._whitelist(f.value, scope, seen)
                        and all(self._safe(a, scope, seen) for a in node.args[1:]))
            if f.attr == "join" and len(node.args) == 1:
                return self._safe(f.value, scope, seen) and self._safe(node.args[0], scope, seen)
            if f.attr == "format":
                return (self._safe(f.value, scope, seen)
                        and all(self._safe(a, scope, seen) for a in node.args)
                        and all(self._safe(k.value, scope, seen) for k in node.keywords))
            if f.attr in self._SAFE_METHODS and not node.args:
                return self._safe(f.value, scope, seen)
            return False
        if isinstance(f, ast.Name) and f.id in ("int", "float", "len") and f.id not in self.funcs:
            return True  # a number carries no SQL: f"... author_id={int(u['id'])}"
        if isinstance(f, ast.Name) and f.id in self.funcs:  # a helper returning SQL
            key = ("ret", f.id)
            if key in seen:
                return True
            fn = self.funcs[f.id]
            rets = [n.value for n in ast.walk(fn) if isinstance(n, ast.Return)]
            return bool(rets) and all(r is not None and self._safe(r, fn, seen | {key}) for r in rets)
        return False

    def _assigned(self, name: str, scope) -> Optional[List[Optional[ast.AST]]]:
        """Every value ``name`` takes in ``scope``: assignments, augmented ones and
        list appends; None for one that can't be known (loop/with target, unpacking).
        None overall when ``name`` is never bound there."""
        nodes = [n for stmt in scope.body for n in ast.walk(stmt)]
        if scope is self.tree:  # module level only, not inside defs
            nodes = [n for n in nodes if self._scope(n) is scope]
        values: List[Optional[ast.AST]] = []
        bound = False

        def binds(target) -> bool:
            return any(isinstance(t, ast.Name) and t.id == name for t in ast.walk(target))

        for n in nodes:
            if isinstance(n, ast.Assign):
                for t in n.targets:
                    if isinstance(t, ast.Name) and t.id == name:
                        values.append(n.value)
                        bound = True
                    elif binds(t) and not isinstance(t, (ast.Attribute, ast.Subscript)):
                        values.append(_unpacked(t, name, n.value))
                        bound = True
            elif isinstance(n, (ast.AugAssign, ast.AnnAssign, ast.NamedExpr)):
                if isinstance(n.target, ast.Name) and n.target.id == name:
                    values.append(n.value)
                    bound = True
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                if binds(n.target):
                    values.append(None)
                    bound = True
            elif isinstance(n, ast.withitem):
                if n.optional_vars is not None and binds(n.optional_vars):
                    values.append(None)
                    bound = True
            elif (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                  and isinstance(n.func.value, ast.Name) and n.func.value.id == name
                  and n.func.attr in ("append", "extend", "insert")):
                values.append(n.args[-1] if n.args else None)
                bound = True
        return values if bound else None

    def _safe_name(self, name: str, scope, seen) -> bool:
        key = (id(scope), name)
        if key in seen:
            return True  # `sql = sql + " ..."`: the other bindings decide
        seen = seen | {key}
        values = self._assigned(name, scope)
        param = self._param(scope, name)
        if values is None and param is None:
            return scope is not self.tree and self._safe_name(name, self.tree, seen)
        if param is not None and not self._safe_param(scope, name, param, seen):
            return False
        return all(v is not None and self._safe(v, scope, seen) for v in values or [])

    def _param(self, scope, name: str):
        """(position, default) of parameter ``name``; position None for keyword-only."""
        if not isinstance(scope, self._FUNCS):
            return None
        a = scope.args
        pos = [*a.posonlyargs, *a.args]
        first_default = len(pos) - len(a.defaults)
        for i, p in enumerate(pos):
            if p.arg == name:
                return i, (a.defaults[i - first_default] if i >= first_default else None)
        for p, dflt in zip(a.kwonlyargs, a.kw_defaults):
            if p.arg == name:
                return None, dflt
        if (a.vararg and a.vararg.arg == name) or (a.kwarg and a.kwarg.arg == name):
            return -1, None
        return None

    def _safe_param(self, fn, name: str, param, seen) -> bool:
        """A parameter is literal when its default is and every call site passes a
        literal. A view nobody calls (its values come from the URL) has no call site,
        so it stays unproven."""
        pos, default = param
        if pos == -1:
            return False
        calls = [n for n in ast.walk(self.tree) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Name) and n.func.id == fn.name]
        if not calls or (default is not None and not self._safe(default, fn, seen)):
            return False
        for c in calls:
            if any(isinstance(a, ast.Starred) for a in c.args) or any(k.arg is None for k in c.keywords):
                return False
            given = next((k.value for k in c.keywords if k.arg == name), None)
            if given is None and pos is not None and pos < len(c.args):
                given = c.args[pos]
            if given is None:
                if default is None:
                    return False
                continue
            if not self._safe(given, self._scope(c), seen):
                return False
        return True


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


_SQLI_LABEL = "SQL Injection"


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
                penalty_reasons=["완전한 인젝션은 아니나 SQL 오류/Stack Trace가 응답에 노출됨"],
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
    Check("sql_parameterization", "Parameterized Query", "static",
          check_sql_parameterization),
    # standard=False: outside --dev this probe RAISES when sqlmap can't run, and that
    # hard-fail must propagate — the runner would otherwise wrap it into a skip.
    Check("sqli", _SQLI_LABEL, "dynamic", dynamic_sqli, standard=False),
]
