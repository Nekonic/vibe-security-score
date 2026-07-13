"""A09 Security Logging and Alerting Failures: reward configured logging that
records auth/error events (static check).
"""
from __future__ import annotations

import re
from typing import Sequence

from ..models import CheckResult
from ..shared.sources import Source, _joined, _mk
from .base import Control


_LOG_CONFIG = re.compile(r"""logging\.basicConfig|logging\.getLogger|app\.logger|dictConfig|RotatingFileHandler""")
_LOG_CALL = re.compile(r"""(?:logger|logging|app\.logger)\.(?:info|warning|error|exception|critical)\s*\(""")


def check_security_logging(sources: Sequence[Source], cfg: dict) -> CheckResult:
    joined = _joined(sources)
    configured = bool(_LOG_CONFIG.search(joined))
    logs_events = bool(_LOG_CALL.search(joined))
    if configured and logs_events:
        return _mk("security_logging", "보안 로깅", float(cfg.get("score_full", 100)),
                   cfg, passed=True, reasons=[], evidence=["logging 설정 + 이벤트 기록"])
    if configured or logs_events:
        return _mk("security_logging", "보안 로깅", float(cfg.get("score_partial", 50)),
                   cfg, passed=False, reasons=["로깅이 부분적으로만 구성됨(인증/오류 이벤트 기록 미흡)"],
                   evidence=[])
    return _mk("security_logging", "보안 로깅", float(cfg.get("score_none", 0)),
               cfg, passed=False,
               reasons=["보안 로깅/모니터링 구성이 없음 → 침해 탐지 불가"], evidence=[])


CONTROLS = [
    Control("security_logging", "보안 로깅", "static",
            lambda sctx, cfg: check_security_logging(sctx.sources, cfg)),
]
