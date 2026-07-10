"""Shared static-analysis helpers: the ``Source`` alias, score clamping, source
text/line scanning, a CheckResult builder, and balanced-argument parsing used by
the source-level controls.
"""
from __future__ import annotations

import os
from typing import Iterable, List, Sequence, Tuple

from ..models import CheckResult

Source = Tuple[str, str]  # (relative_path, file_text)


def _clamp(score: float) -> float:
    return max(0.0, min(100.0, score))


def _iter_lines(sources: Sequence[Source]) -> Iterable[Tuple[str, int, str]]:
    for path, text in sources:
        for i, line in enumerate(text.splitlines(), start=1):
            yield path, i, line


def _joined(sources: Sequence[Source]) -> str:
    return "\n".join(text for _, text in sources)


def _mk(check_id: str, label: str, score: float, cfg: dict, *,
        passed: bool, reasons: List[str], evidence: List[str]) -> CheckResult:
    return CheckResult(
        check_id=check_id, category="static", label=label,
        score=_clamp(score), weight=float(cfg.get("weight", 0)),
        passed=passed, penalty_reasons=reasons, evidence=evidence,
    )


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


def _read_tree(root: str, base: str, match) -> List[Source]:
    """Collect (relpath, text) for files under ``root`` whose name passes ``match``,
    with relpaths relative to ``base``."""
    out: List[Source] = []
    if not os.path.isdir(root):
        return out
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not match(fn):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    out.append((rel, fh.read()))
            except OSError:
                continue
    return out
