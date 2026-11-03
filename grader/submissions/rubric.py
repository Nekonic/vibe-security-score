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


_META: dict = {}


def _meta():
    """Config-driven category order/labels + per-check standard tags (loaded once)."""
    if not _META:
        try:
            from scoring.config import load_config
            cfg = load_config()
            _META.update(order=list(cfg.category_labels.keys()), labels=cfg.category_labels,
                         standards=cfg.get("standards", {}) or {})
        except Exception:
            _META.update(order=[], labels={}, standards={})
    return _META


def breakdown(sub: Submission):
    """Result-page breakdown: per-category points (earned / max, summing to the raw
    score) and, per check, the real points it lost plus its standard tags. Weight-0
    categories and checks go to ``reference`` (shown, never scored)."""
    meta = _meta()
    by_cat: dict = {}
    for f in sub.findings or []:
        if not f.get("skipped"):
            by_cat.setdefault(f.get("category", ""), []).append(f)
    crit = {p.get("check_id"): p.get("penalty") for p in sub.critical_penalties or []}
    domains, reference = [], []
    for cat in meta["order"] + [c for c in by_cat if c not in meta["order"]]:
        items = by_cat.get(cat)
        if not items:
            continue
        label = meta["labels"].get(cat) or items[0].get("category_label") or cat
        # The category's share of the final score, stamped on each finding at grading.
        share = max(float(f.get("category_weight", 0) or 0) for f in items)
        if share == 0:
            reference += items
            continue
        scored = [f for f in items if float(f.get("weight", 0) or 0) > 0]
        reference += [f for f in items if f not in scored]
        if not scored:
            continue
        max_points = share * 100.0
        tw = sum(float(f["weight"]) for f in scored)
        rows = []
        for f in scored:
            row = dict(f, tags=meta["standards"].get(f.get("check_id"), []),
                       critical=crit.get(f.get("check_id")))
            pts = max_points * float(f["weight"]) / tw
            row["points"] = round(pts, 1)
            row["lost"] = round(pts * (100.0 - float(f.get("score", 0))) / 100.0, 1)
            rows.append(row)
        rows.sort(key=lambda r: (-r["lost"], r.get("label", "")))
        lost = [r for r in rows if not r.get("passed") or r["lost"] > 0]
        earned = max_points - sum(r["lost"] for r in rows)
        domains.append({
            "key": cat, "label": label,
            "max_points": round(max_points, 1),
            # + 0.0 turns a rounded -0.0 into 0.0 so the page never shows "-0.0".
            "earned": round(max(earned, 0.0), 1) + 0.0,
            "pct": round(100.0 * earned / max_points),
            "failed": lost, "passed": [r for r in rows if r not in lost],
        })
    return {"domains": domains, "reference": reference}
