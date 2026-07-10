"""Pure-Python scoring library (static + dynamic). No Django imports."""
from .config import Config, load_config
from .models import CheckResult, CategoryResult, GradeResult
from .aggregate import combine_scores
from .grade import grade_submission, build_report

__all__ = [
    "Config",
    "load_config",
    "CheckResult",
    "CategoryResult",
    "GradeResult",
    "combine_scores",
    "grade_submission",
    "build_report",
]
