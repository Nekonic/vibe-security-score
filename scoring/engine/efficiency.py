"""Prompt efficiency: the challenge is ONE prompt, so the same security from a
shorter prompt is worth more. final = security score × multiplier(prompt chars).

Multiplicative on purpose: a short prompt that secures nothing gains nothing, and
a long prompt can never out-rank a shorter one that secures as much.
"""
from __future__ import annotations

from typing import Any, Dict

from ..config import Config


def multiplier(prompt_chars: int, config: Config) -> float:
    """1.0 up to ``efficiency.free_chars``, then linear down to ``min_multiplier`` at
    ``submission.max_prompt_chars`` (the input cap)."""
    free = float(config.get("efficiency.free_chars", 200))
    floor = float(config.get("efficiency.min_multiplier", 0.8))
    cap = float(config.get("submission.max_prompt_chars", 1000) or 1000)
    if prompt_chars <= free or cap <= free:
        return 1.0
    over = min(prompt_chars, cap) - free
    return round(1.0 - (1.0 - floor) * over / (cap - free), 4)


def apply(report: Dict[str, Any], prompt_chars: int, config: Config) -> Dict[str, Any]:
    """Return ``report`` with the efficiency multiplier folded into the final score
    (unchanged when the feature is disabled)."""
    if not config.get("efficiency.enabled", False):
        return report
    security = float(report.get("final_score", 0.0))
    m = multiplier(int(prompt_chars), config)
    final = round(security * m, 2)
    return {
        **report,
        "security_score": security,
        "prompt_chars": int(prompt_chars),
        "efficiency": m,
        "final_score": final,
    }
