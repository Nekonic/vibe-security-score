"""CLI: python -m scoring.cli {static|dynamic|grade} <app_dir>."""
from __future__ import annotations

import argparse
import json
import sys

from .aggregate import combine_scores
from .config import load_config
from .dynamic.runner import run_dynamic
from .static.runner import run_static


def _load(config_path: str | None):
    return load_config(config_path) if config_path else load_config()


def _print_report(report: dict) -> None:
    print(json.dumps(report, ensure_ascii=False, indent=2))


def _cmd_static(app_dir: str, config_path: str | None) -> int:
    config = _load(config_path)
    check_results = run_static(app_dir, config)
    grade = combine_scores(check_results, config, functional_failed=False, boot_failed=False)

    _print_report({
        "app_dir": app_dir,
        "final_score": round(grade.score, 2),
        "grade": grade.grade,
        "capped": grade.capped,
        "checks": [c.to_dict() for c in check_results],
        "result": grade.to_dict(),
    })
    return 0


def _cmd_dynamic(app_dir: str, config_path: str | None) -> int:
    config = _load(config_path)
    checks, functional_failed, boot_failed = run_dynamic(app_dir, config)
    grade = combine_scores(
        checks, config, functional_failed=functional_failed, boot_failed=boot_failed
    )

    _print_report({
        "app_dir": app_dir,
        "final_score": round(grade.score, 2),
        "grade": grade.grade,
        "capped": grade.capped,
        "cap_reason": grade.cap_reason,
        "functional_failed": functional_failed,
        "boot_failed": boot_failed,
        "checks": [c.to_dict() for c in checks],
        "result": grade.to_dict(),
    })
    return 0


def _cmd_grade(app_dir: str, config_path: str | None) -> int:
    config = _load(config_path)
    static_checks = run_static(app_dir, config)
    dynamic_checks, functional_failed, boot_failed = run_dynamic(app_dir, config)
    all_checks = static_checks + dynamic_checks

    grade = combine_scores(
        all_checks, config, functional_failed=functional_failed, boot_failed=boot_failed
    )

    print(f"=== {app_dir} ===")
    print(f"최종 점수: {round(grade.score, 2)}  등급: {grade.grade}"
          + (f"  (상한 적용: {grade.cap_reason})" if grade.capped else ""))
    print(f"boot_failed={boot_failed}  functional_failed={functional_failed}")
    for cat in grade.categories:
        print(f"\n[{cat.name}] 점수 {round(cat.score, 2)} (가중치 {round(cat.weight, 3)})")
        for c in cat.checks:
            mark = "✔" if c.passed else "✘"
            print(f"  {mark} {c.check_id:<22} {round(c.score, 1):>6}  {c.label}")
            for reason in c.penalty_reasons:
                print(f"        - {reason}")

    print()
    _print_report({
        "app_dir": app_dir,
        "final_score": round(grade.score, 2),
        "grade": grade.grade,
        "capped": grade.capped,
        "cap_reason": grade.cap_reason,
        "functional_failed": functional_failed,
        "boot_failed": boot_failed,
        "result": grade.to_dict(),
    })
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scoring.cli", description="Security scorer")
    sub = parser.add_subparsers(dest="command", required=True)

    for name, helptext in (
        ("static", "Run static analysis on an app directory"),
        ("dynamic", "Boot the app in a sandbox and attack it (dynamic only)"),
        ("grade", "Run static + dynamic and print the combined score/grade"),
    ):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("app_dir", help="Path to the participant app directory")
        p.add_argument("--config", default=None, help="Path to scoring.yaml (default: config/scoring.yaml)")

    args = parser.parse_args(argv)
    if args.command == "static":
        return _cmd_static(args.app_dir, args.config)
    if args.command == "dynamic":
        return _cmd_dynamic(args.app_dir, args.config)
    if args.command == "grade":
        return _cmd_grade(args.app_dir, args.config)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
