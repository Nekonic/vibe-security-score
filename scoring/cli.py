"""CLI: python -m scoring.cli {static|dynamic|grade} <app_dir>."""
from __future__ import annotations

import argparse
import json
import sys

from .config import load_config
from .engine import combine_scores, run_dynamic, run_static
from .shared.external_tools import missing_required_tools


def _load(config_path: str | None, dev: bool = False):
    config = load_config(config_path) if config_path else load_config()
    config.dev = bool(dev)
    if not dev:
        missing = missing_required_tools(config)
        if missing:
            print(
                f"[error] 필수 외부 도구가 설치되어 있지 않습니다: {', '.join(missing)}. "
                "설치 후 다시 실행하거나, 내장 검사로 돌리려면 --dev 를 사용하세요(권장하지 않음).",
                file=sys.stderr,
            )
            raise SystemExit(2)
    return config


def _print_report(report: dict) -> None:
    print(json.dumps(report, ensure_ascii=False, indent=2))


def _cmd_static(app_dir: str, config_path: str | None, dev: bool = False) -> int:
    config = _load(config_path, dev)
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


def _cmd_dynamic(app_dir: str, config_path: str | None, dev: bool = False) -> int:
    config = _load(config_path, dev)
    checks, functional_failed, boot_failed, boot_log = run_dynamic(app_dir, config)
    if boot_log:
        header = "부팅 실패 로그" if boot_failed else "런타임 로그(기능 게이트 실패)"
        print(f"=== {header} ===\n" + boot_log + "\n", file=sys.stderr)
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
        "boot_log": boot_log,
        "checks": [c.to_dict() for c in checks],
        "result": grade.to_dict(),
    })
    return 0


def _cmd_grade(app_dir: str, config_path: str | None, dev: bool = False) -> int:
    config = _load(config_path, dev)
    static_checks = run_static(app_dir, config)
    dynamic_checks, functional_failed, boot_failed, boot_log = run_dynamic(app_dir, config)
    all_checks = static_checks + dynamic_checks

    grade = combine_scores(
        all_checks, config, functional_failed=functional_failed, boot_failed=boot_failed
    )

    print(f"=== {app_dir} ===")
    print(f"최종 점수: {round(grade.score, 2)} / 100  등급: {grade.grade}"
          + (f"  (상한 적용: {grade.cap_reason})" if grade.capped else ""))
    if boot_failed and boot_log:
        print("--- 부팅 실패 로그 ---")
        print(boot_log)
        print("---------------------")
    if grade.critical_penalties:
        deducted = round(grade.raw_score - grade.score, 2)
        print(f"기본 점수 {round(grade.raw_score, 2)} − 치명 감점 {deducted} = {round(grade.score, 2)}")
        for p in grade.critical_penalties:
            print(f"  −{p.penalty:<5} {p.check_id:<22} {p.severity}")
    print(f"boot_failed={boot_failed}  functional_failed={functional_failed}")
    for cat in grade.categories:
        max_points = round(cat.weight * 100.0, 1)      # category's share of 100
        earned = round(cat.score / 100.0 * max_points, 1)
        print(f"\n[{cat.name}] {earned} / {max_points}점  (내부 {round(cat.score, 1)}/100)")
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
        p.add_argument("--dev", action="store_true",
                       help="Run REAL external tools (osv-scanner/gitleaks/semgrep/sqlmap). "
                            "Default: off — warn and use built-in offline checks.")

    args = parser.parse_args(argv)
    if args.command == "static":
        return _cmd_static(args.app_dir, args.config, args.dev)
    if args.command == "dynamic":
        return _cmd_dynamic(args.app_dir, args.config, args.dev)
    if args.command == "grade":
        return _cmd_grade(args.app_dir, args.config, args.dev)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    sys.exit(main())
