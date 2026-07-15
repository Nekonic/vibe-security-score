"""Result-page rubric shaping: turn a submission's raw findings into the
visible, worst-first list and the per-category weighted breakdown. Config-driven
(category order/labels/weights come from scoring.yaml), never scores anything."""
from __future__ import annotations

from .models import Submission


def visible_findings(sub: Submission):
    """Scored findings only (drop skipped + zero-weight aux), worst-first."""
    items = [
        f
        for f in (sub.findings or [])
        if not f.get("skipped") and float(f.get("weight", 0) or 0) > 0
    ]
    items.sort(key=lambda f: (f.get("passed") is True, f.get("score", 0)))
    return items


_CATEGORY_ORDER: list = []
_CATEGORY_LABELS: dict = {}
_CATEGORY_WEIGHTS: dict = {}


def _category_meta():
    """Config-driven rubric category order + labels + normalized weights (once)."""
    global _CATEGORY_ORDER, _CATEGORY_LABELS, _CATEGORY_WEIGHTS
    if not _CATEGORY_ORDER:
        try:
            from scoring.config import load_config
            cfg = load_config()
            _CATEGORY_LABELS = cfg.category_labels
            _CATEGORY_ORDER = list(cfg.category_labels.keys())
            _CATEGORY_WEIGHTS = cfg.category_weights
        except Exception:
            _CATEGORY_LABELS, _CATEGORY_ORDER, _CATEGORY_WEIGHTS = {}, [], {}
    return _CATEGORY_ORDER, _CATEGORY_LABELS


def category_groups(sub: Submission):
    """Group visible findings into rubric categories (config order), each with its
    weighted-average score — the per-category breakdown of the rubric."""
    findings = visible_findings(sub)
    order, labels = _category_meta()
    by_cat: dict = {}
    for f in findings:
        by_cat.setdefault(f.get("category", ""), []).append(f)
    ordered = order + [c for c in by_cat if c not in order]
    groups = []
    for cat in ordered:
        items = by_cat.get(cat)
        if not items:
            continue
        tw = sum(float(i.get("weight", 0) or 0) for i in items)
        score = (sum(float(i.get("score", 0)) * float(i.get("weight", 0) or 0) for i in items) / tw) if tw else 0.0
        label = items[0].get("category_label") or labels.get(cat, cat)
        # Show real points (e.g. 8.7 / 15), not a 0-100 scale. max_points is the
        # category's share of 100; earned scales by the 0-100 category score.
        max_points = round(_CATEGORY_WEIGHTS.get(cat, 0.0) * 100.0, 1)
        earned = round(score / 100.0 * max_points, 1)
        groups.append({
            "key": cat, "label": label, "score": round(score, 1),
            "earned": earned, "max_points": max_points, "findings": items,
        })
    return groups
