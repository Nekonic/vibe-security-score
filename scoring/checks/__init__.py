"""Security checks organized by OWASP 2025 family, plus the single registry.

Each ``A0N_*`` module co-locates a family's static checks and dynamic probes and
exports a ``CHECKS`` list; this package assembles them once, in family order, into
``CHECKS``. The engine filters that list by phase via :func:`by_phase`. Adding a
check means editing one family module — nothing here.
"""
from __future__ import annotations

from typing import List

from . import (
    A01_broken_access_control, A02_security_misconfiguration, A03_supply_chain,
    A04_cryptographic_failures, A05_injection_csv, A05_injection_sql, A05_injection_xss,
    A06_insecure_design, A07_account_recovery, A07_authentication_failures, A07_reset_link,
    A08_integrity_failures,
    A09_logging_failures, A10_exceptional_conditions, sast,
)
from .base import Check

CHECKS: List[Check] = [
    # First after functional: the reset-token takeover needs writes that a locked-up
    # app refuses later in the run.
    *A07_account_recovery.EARLY,
    # The reset-link Host check signs up a fresh account and resets its password:
    # early for the same reason.
    *A07_reset_link.CHECKS,
    *A01_broken_access_control.CHECKS,
    *A02_security_misconfiguration.CHECKS,
    *A03_supply_chain.CHECKS,
    *A04_cryptographic_failures.CHECKS,
    *A05_injection_sql.CHECKS,
    *A05_injection_xss.CHECKS,
    *A05_injection_csv.CHECKS,
    *A07_authentication_failures.CHECKS,
    *A08_integrity_failures.CHECKS,
    *A09_logging_failures.CHECKS,
    *A10_exceptional_conditions.CHECKS,
    *sast.CHECKS,
    *A06_insecure_design.CHECKS,
]


def by_phase(phase: str) -> List[Check]:
    """Return the checks whose ``phase`` matches (``"static"`` or ``"dynamic"``)."""
    return [c for c in CHECKS if c.phase == phase]
