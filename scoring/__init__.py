"""Pure-Python scoring library (static + dynamic). No Django imports.

Public surface: everything here plus ``scoring.config``. The ``engine``, ``checks``,
and ``shared`` subpackages are internal implementation.
"""
from .config import Config, load_config
from .models import CategoryResult, CheckResult, GradeResult
from .engine import build_report, combine_scores, grade_submission, progress

__all__ = [
    "Config",
    "load_config",
    "CheckResult",
    "CategoryResult",
    "GradeResult",
    "combine_scores",
    "grade_submission",
    "build_report",
    "progress",
]
