"""The Control declaration shared by every family module and the registry.

A Control couples a check/probe function to its id, display label, and execution
phase. ``owasp`` is derived from the single source of truth in ``scoring.owasp``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ..owasp import code_for


@dataclass(frozen=True)
class Control:
    id: str
    label: str
    phase: str  # "static" | "dynamic"
    fn: Callable

    @property
    def owasp(self) -> str:
        return code_for(self.id)
