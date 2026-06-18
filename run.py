#!/usr/bin/env python3
"""Orchestrator CLI for vibe-security-score.

Usage:
    python run.py --code <submission_dir> [--json out.json]

The submission directory contains both the generated code (with
requirements.txt) and the participant's prompt as `prompt.md`.

Calls each analysis module (each returns {score, findings, ...}), computes the
weighted final via report.build_result (which applies the functional gate cap),
then prints the human report and optionally writes the JSON.

The orchestrator is defensive: a module that raises is recorded as a 0-score
finding rather than crashing the whole run, so one broken check can't sink the
grader. Functional results drive the gate.
"""
from __future__ import annotations

import argparse
import os
import sys
import traceback

import config
import report
from modules import secure_coding, dependencies, prompt_quality, functional


def _safe(name: str, fn, *args, default_gate: bool | None = None) -> dict:
    """Run a module's analyze(), trapping exceptions into a degraded result."""
    try:
        res = fn(*args)
        if "score" not in res:
            res["score"] = 0.0
        if "findings" not in res:
            res["findings"] = []
        return res
    except Exception as exc:  # noqa: BLE001 — never let one module sink the run
        tb = traceback.format_exc(limit=3)
        finding = {
            "id": f"{name}_error",
            "label": f"{name} module error",
            "passed": False,
            "penalty": 0,
            "reason": f"채점 모듈 실행 중 예외 발생 — 검사 생략 처리. {exc}",
            "evidence": tb.strip().splitlines()[-1] if tb else str(exc),
            "skipped": True,
        }
        out = {"score": 0.0, "findings": [finding]}
        if default_gate is not None:
            out["gate_passed"] = default_gate
        return out


def grade(code_dir: str, prompt_text: str) -> dict:
    module_results: dict[str, dict] = {}

    module_results["secure_coding"] = _safe(
        "secure_coding", secure_coding.analyze, code_dir)
    module_results["dependencies"] = _safe(
        "dependencies", dependencies.analyze, code_dir)
    module_results["prompt_quality"] = _safe(
        "prompt_quality", prompt_quality.analyze, prompt_text)
    module_results["functional"] = _safe(
        "functional", functional.analyze, code_dir, default_gate=False)

    return report.build_result(module_results, prompt_provided=bool(prompt_text.strip()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="vibe-security-score",
        description="Score the security of an AI-generated Flask auth app.")
    parser.add_argument("--code", required=True,
                        help="Path to the submission directory (generated code + "
                             f"requirements.txt + {config.PROMPT_FILENAME}).")
    parser.add_argument("--json", dest="json_out", default=None,
                        help="Also write the machine-readable JSON to this file.")
    args = parser.parse_args(argv)

    # The prompt lives inside the submission directory as PROMPT_FILENAME.
    prompt_text = ""
    prompt_path = os.path.join(args.code, config.PROMPT_FILENAME)
    try:
        with open(prompt_path, "r", encoding="utf-8", errors="replace") as fh:
            prompt_text = fh.read()
    except OSError:
        print(f"warning: no {config.PROMPT_FILENAME} found in submission directory "
              f"({prompt_path}); prompt_quality will score 0.", file=sys.stderr)

    result = grade(args.code, prompt_text)

    print(report.render_text(result))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(report.to_json(result))
        print(f"\n[json written to {args.json_out}]", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
