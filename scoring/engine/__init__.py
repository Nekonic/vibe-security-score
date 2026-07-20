"""Execution pipeline: gather inputs -> run checks by phase -> aggregate -> grade.

Consumes ``scoring.checks`` (the registry) and ``scoring.shared`` (plumbing); the
top-level package and CLI import the engine only through the names re-exported here.
"""
from __future__ import annotations

from . import progress
from .aggregate import combine_scores
from .grade import build_report, grade_submission
from .runner import StaticContext, boot_sandbox, run_dynamic, run_static

__all__ = [
    "progress",
    "combine_scores",
    "grade_submission",
    "build_report",
    "StaticContext",
    "boot_sandbox",
    "run_dynamic",
    "run_static",
]
