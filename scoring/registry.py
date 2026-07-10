"""The single control registry: every static check and dynamic probe declared
once, in OWASP-family order. Runners filter this list by phase.
"""
from __future__ import annotations

from typing import List

from .controls import (
    access_control, auth, crypto, dependencies, design, exceptions, integrity,
    logging, misconfig, sast,
)
from .controls.base import Control
from .controls.injection import sql, xss

CONTROLS: List[Control] = [
    *access_control.CONTROLS,  # A01
    *misconfig.CONTROLS,       # A02
    *dependencies.CONTROLS,    # A03
    *crypto.CONTROLS,          # A04
    *sql.CONTROLS,             # A05 (SQL)
    *xss.CONTROLS,             # A05 (XSS)
    *design.CONTROLS,          # A06
    *auth.CONTROLS,            # A07
    *integrity.CONTROLS,       # A08
    *logging.CONTROLS,         # A09
    *exceptions.CONTROLS,      # A10
    *sast.CONTROLS,            # general SAST
]


def by_phase(phase: str) -> List[Control]:
    return [c for c in CONTROLS if c.phase == phase]
