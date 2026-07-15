"""A08 Software or Data Integrity Failures: insecure deserialization / dynamic
exec on request data (static check).
"""
from __future__ import annotations

import re
from typing import List, Sequence

from ..models import CheckResult
from ..shared.sources import Source, _mk
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
        uses_request = bool(_REQUEST_NEAR.search(text))
        for m in _INSECURE_DESER.finditer(text):
            token = m.group(0)
            # eval/exec only matter if the app also handles request data.
            if token.lower().startswith(("eval", "exec")) and not uses_request:
                continue
            lineno = text.count("\n", 0, m.start()) + 1
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
