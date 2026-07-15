"""The Check declaration shared by every family module and the registry.

A Check couples a check/probe function to its id, display label, and execution
phase. The OWASP tag is derived at aggregation time from ``scoring.owasp``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Check:
    id: str
    label: str
    phase: str  # "static" | "dynamic"
    fn: Callable
