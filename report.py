"""Rendering: human-readable report (stdout) + machine-readable JSON.

The deduction reasons are the educational payload, so the human report leads with
them. Pure formatting — no scoring decisions are made here (those live in run.py
using values from config.py).
"""
from __future__ import annotations

import json

import config

CHECK = "✔"   # ✔
CROSS = "✘"   # ✘
SKIP = "➖"    # ➖ (skipped / could not run)

MODULE_TITLES = {
    "secure_coding": "Secure Coding (static)",
    "dependencies": "Dependencies (CVE + typosquatting)",
    "prompt_quality": "Prompt Quality",
    "functional": "Functional (dynamic gate)",
}


def _mark(finding: dict) -> str:
    if finding.get("skipped"):
        return SKIP
    return CHECK if finding.get("passed") else CROSS


def grade_for(score: float) -> str:
    for grade, minimum in config.GRADE_BANDS:
        if score >= minimum:
            return grade
    return config.GRADE_BANDS[-1][0]


def build_result(module_results: dict, prompt_provided: bool) -> dict:
    """Compute the weighted final, gate cap, grade and PASS/FAIL.

    module_results: {module_name: {"score":.., "findings":[..], ...}}
    Returns the full machine-readable result dict.
    """
    weights = config.MODULE_WEIGHTS
    weighted_breakdown = {}
    weighted_sum = 0.0
    for name, weight in weights.items():
        sub = float(module_results.get(name, {}).get("score", 0.0))
        contribution = sub * weight
        weighted_sum += contribution
        weighted_breakdown[name] = {
            "sub_score": round(sub, 2),
            "weight": weight,
            "weighted": round(contribution, 2),
        }

    gate_passed = bool(module_results.get("functional", {}).get("gate_passed", False))

    final = weighted_sum
    gate_capped = False
    if not gate_passed and final > config.FUNCTIONAL_GATE_CAP:
        final = config.FUNCTIONAL_GATE_CAP
        gate_capped = True

    final = round(final, 2)
    grade = grade_for(final)
    passed = bool(final >= config.PASS_THRESHOLD and gate_passed)

    return {
        "final_score": final,
        "grade": grade,
        "passed": passed,
        "gate_passed": gate_passed,
        "gate_capped": gate_capped,
        "gate_cap_value": config.FUNCTIONAL_GATE_CAP,
        "weighted_sum": round(weighted_sum, 2),
        "weights": weights,
        "breakdown": weighted_breakdown,
        "prompt_provided": prompt_provided,
        "modules": module_results,
    }


def render_text(result: dict) -> str:
    lines: list[str] = []
    add = lines.append

    add("=" * 70)
    add("  vibe-security-score  —  Security Grading Report")
    add("=" * 70)

    for name in config.MODULE_WEIGHTS:
        mod = result["modules"].get(name, {})
        title = MODULE_TITLES.get(name, name)
        sub = result["breakdown"][name]
        add("")
        add(f"[{title}]  sub-score: {sub['sub_score']:.1f}/100"
            f"   weight: {sub['weight']:.0%}   weighted: {sub['weighted']:.1f}")
        add("-" * 70)
        findings = mod.get("findings", [])
        if not findings:
            add("  (no findings reported)")
        for f in findings:
            mark = _mark(f)
            label = f.get("label", f.get("id", "?"))
            pen = f.get("penalty", 0) or 0
            pen_str = f"  (-{pen})" if pen else ""
            add(f"  {mark} {label}{pen_str}")
            reason = f.get("reason")
            if reason:
                add(f"      → {reason}")
            ev = f.get("evidence")
            if ev:
                add(f"        evidence: {ev}")
        if name == "functional":
            gp = mod.get("gate_passed")
            add(f"  GATE: {'PASSED' if gp else 'FAILED'}")

    add("")
    add("=" * 70)
    add("  SCORING")
    add("-" * 70)
    for name in config.MODULE_WEIGHTS:
        b = result["breakdown"][name]
        add(f"  {MODULE_TITLES.get(name, name):<34} "
            f"{b['sub_score']:6.1f} x {b['weight']:.2f} = {b['weighted']:6.2f}")
    add(f"  {'weighted sum':<34} {result['weighted_sum']:>21.2f}")
    if result["gate_capped"]:
        add(f"  GATE FAILED → final capped at {result['gate_cap_value']}")
    add("-" * 70)
    add(f"  FINAL SCORE : {result['final_score']:.2f} / 100")
    add(f"  GRADE       : {result['grade']}")
    add(f"  RESULT      : {'PASS' if result['passed'] else 'FAIL'}")
    add("=" * 70)
    return "\n".join(lines)


def to_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)
