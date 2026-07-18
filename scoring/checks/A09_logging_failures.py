"""A09 Security Logging and Alerting Failures: reward configured logging that
records auth/error events (static check).
"""
from __future__ import annotations

import re

from ..shared.sources import _joined
from .base import Check, result


# ── security_logging  (static) ─────────────────────────────────────────────
_LOG_CONFIG = re.compile(r"""logging\.basicConfig|logging\.getLogger|app\.logger|dictConfig|RotatingFileHandler""")
_LOG_CALL = re.compile(r"""(?:logger|logging|app\.logger)\.(?:info|warning|error|exception|critical)\s*\(""")


def check_security_logging(check: Check, sctx, cfg: dict):
    joined = _joined(sctx.sources)
    configured = bool(_LOG_CONFIG.search(joined))
    logs_events = bool(_LOG_CALL.search(joined))
    if configured and logs_events:
        return result(check, cfg, score=cfg.get("score_full", 100), passed=True,
                      evidence=["logging 설정 + 이벤트 기록"])
    if configured or logs_events:
        return result(check, cfg, score=cfg.get("score_partial", 50), passed=False,
                      reasons=["로깅이 부분적으로만 구성됨(인증/오류 이벤트 기록 미흡)"])
    return result(check, cfg, score=cfg.get("score_none", 0), passed=False,
                  reasons=["보안 로깅/모니터링 구성이 없음 → 침해 탐지 불가"])


CHECKS = [
    Check("security_logging", "보안 로깅", "static", check_security_logging),
]
