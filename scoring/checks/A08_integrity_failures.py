"""A08 Software or Data Integrity Failures: insecure deserialization / dynamic
exec on request data (static check).
"""
from __future__ import annotations

import re
from typing import List

from ..shared.sources import _balanced_arg
from .base import Check, result


# ── insecure_deserialization  (static) ─────────────────────────────────────
_INSECURE_DESER = re.compile(
    r"""pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)|(?<![\w.])(eval|exec)\s*\(""",
    re.IGNORECASE,
)
_REQUEST_NEAR = re.compile(r"""request\.|request\[""")


def check_insecure_deserialization(check: Check, sctx, cfg: dict):
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sctx.sources:
        lines = text.splitlines()
        for m in _INSECURE_DESER.finditer(text):
            token = m.group(0)
            lineno = text.count("\n", 0, m.start()) + 1
            if token.lower().startswith(("eval", "exec")) and not _takes_request_input(text, lines, m.start(), lineno):
                continue
            reasons.append(f"{path}:{lineno} 안전하지 않은 역직렬화/동적 실행: {token.strip()}")
            evidence.append(f"{path}:{lineno}: {token.strip()}")
    if reasons:
        return result(check, cfg, score=cfg.get("score_found", 0), passed=False,
                      reasons=reasons, evidence=evidence)
    return result(check, cfg, score=cfg.get("score_clean", 100), passed=True)


def _takes_request_input(text: str, lines: List[str], start: int, lineno: int) -> bool:
    """eval/exec is a finding only when THIS call takes request-derived input (its
    own argument or its line references request) — not merely because the file
    handles requests elsewhere."""
    open_idx = text.find("(", start)
    arg = _balanced_arg(text, open_idx) if open_idx != -1 else ""
    line = lines[lineno - 1] if 0 <= lineno - 1 < len(lines) else ""
    return bool(_REQUEST_NEAR.search(arg) or _REQUEST_NEAR.search(line))


CHECKS = [
    Check("insecure_deserialization", "안전하지 않은 역직렬화", "static",
          check_insecure_deserialization),
]
