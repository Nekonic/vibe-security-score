"""A08 Software or Data Integrity Failures: insecure deserialization / dynamic
exec on request data (static check).
"""
from __future__ import annotations

import re
from typing import List, Sequence

from ..models import CheckResult
from ..shared.sources import Source, _balanced_arg, _mk
from .base import Check


_INSECURE_DESER = re.compile(
    r"""pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)|(?<![\w.])(eval|exec)\s*\(""",
    re.IGNORECASE,
)
_REQUEST_NEAR = re.compile(r"""request\.|request\[""")


def check_insecure_deserialization(sources: Sequence[Source], cfg: dict) -> CheckResult:
    reasons: List[str] = []
    evidence: List[str] = []
    for path, text in sources:
        lines = text.splitlines()
        for m in _INSECURE_DESER.finditer(text):
            token = m.group(0)
            lineno = text.count("\n", 0, m.start()) + 1
            # eval/exec are only a finding if THIS call takes request-derived input
            # (its own argument or line references request) — not merely because the
            # file handles requests somewhere unrelated.
            if token.lower().startswith(("eval", "exec")):
                open_idx = text.find("(", m.start())
                arg = _balanced_arg(text, open_idx) if open_idx != -1 else ""
                line = lines[lineno - 1] if 0 <= lineno - 1 < len(lines) else ""
                if not (_REQUEST_NEAR.search(arg) or _REQUEST_NEAR.search(line)):
                    continue
            reasons.append(f"{path}:{lineno} 안전하지 않은 역직렬화/동적 실행: {token.strip()}")
            evidence.append(f"{path}:{lineno}: {token.strip()}")
    if reasons:
        return _mk("insecure_deserialization", "안전하지 않은 역직렬화",
                   float(cfg.get("score_found", 0)), cfg,
                   passed=False, reasons=reasons, evidence=evidence)
    return _mk("insecure_deserialization", "안전하지 않은 역직렬화",
               float(cfg.get("score_clean", 100)), cfg,
               passed=True, reasons=[], evidence=[])


CHECKS = [
    Check("insecure_deserialization", "안전하지 않은 역직렬화", "static",
            lambda sctx, cfg: check_insecure_deserialization(sctx.sources, cfg)),
]
