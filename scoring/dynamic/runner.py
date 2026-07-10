"""Dynamic runner: boot the app in a sandbox, run the attack probes.

On boot failure we still return the five dynamic CheckResults (scored 0) so
aggregation stays uniform — the ``boot_failed`` flag caps the final score.
"""
from __future__ import annotations

import time
from typing import List, Tuple

import os
import tempfile

from ..config import Config
from ..models import CheckResult
from ..static import dependency_checks as dc
from ..static import tools as tools_mod
from . import probes as pb
from .container import Sandbox

_DYNAMIC_CHECK_IDS = (
    "functional", "idor_profile", "access_control_admin", "stored_xss",
    "reflected_xss", "sqli", "transport_security", "rate_limiting",
    "weak_password_policy", "verbose_errors", "session_forgery",
)
_LABELS = {
    "functional": "기능 게이트(회원가입/로그인/글작성)",
    "idor_profile": "IDOR(타인 프로필 조회)",
    "access_control_admin": "접근 통제(관리자 페이지)",
    "stored_xss": "저장형 XSS",
    "reflected_xss": "반사형 XSS",
    "sqli": "SQL 인젝션(/search, /posts sort)",
    "transport_security": "전송/응답 보안(헤더·쿠키 플래그)",
    "rate_limiting": "무차별 대입 방어(Rate limiting)",
    "weak_password_policy": "비밀번호 정책",
    "verbose_errors": "오류 처리(스택트레이스 노출)",
    "session_forgery": "세션 위조 검증(약한 SECRET_KEY)",
}


def _resolved_cve(box: Sandbox, config: Config) -> CheckResult:
    """Recompute the A03 CVE check against the container's REAL resolved (transitive)
    package versions from `pip freeze`. In --dev this runs osv-scanner on those
    versions; otherwise the deterministic local snapshot. tool marks it as resolved
    so aggregation prefers it over the requirements-only static result."""
    dep_cfg = dict(config.get("static.dependencies", {}) or {})
    dep_weight = float(dep_cfg.get("weight", 0))
    # CVE's share of the dependencies pool (same split as the static runner).
    dep_cfg["weight"] = float((dep_cfg.get("cve") or {}).get("weight", dep_weight / 2.0))
    freeze = box.pip_freeze()
    requirements = dc.parse_requirements(freeze)
    if not requirements:
        result = dc.check_cve([], dep_cfg)
        result.tool = "pip-freeze"
        result.label = "의존성 CVE(실측 전이 포함)"
        result.evidence = ["pip freeze 실패 → 정적 requirements 결과 유지"]
        return result

    # Write resolved versions to a temp lockfile so osv-scanner (dev) can scan them.
    tmp = tempfile.NamedTemporaryFile("w", suffix="_requirements.txt", delete=False, encoding="utf-8")
    try:
        tmp.write(freeze)
        tmp.close()
        result = tools_mod.check_cve_with_osv(requirements, dep_cfg, tmp.name, config)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    result.tool = "pip-freeze" if result.tool != "osv-scanner" else "osv-scanner+freeze"
    result.label = "의존성 CVE(실측 전이 포함)"
    return result


def _boot_failed_checks(config: Config, reason: str) -> List[CheckResult]:
    dyn = config.get("dynamic.checks", {}) or {}
    out: List[CheckResult] = []
    for cid in _DYNAMIC_CHECK_IDS:
        weight = float((dyn.get(cid, {}) or {}).get("weight", 0))
        out.append(
            CheckResult(
                check_id=cid, category="dynamic", label=_LABELS[cid],
                score=0.0, weight=weight, passed=False,
                penalty_reasons=[f"앱 부팅 실패로 동적 검사 불가: {reason}"],
                evidence=[],
            )
        )
    return out


def run_dynamic(app_dir: str, config: Config) -> Tuple[List[CheckResult], bool, bool]:
    dyn_cfg = config.get("dynamic.checks", {}) or {}
    require = list(config.get("gates.functional.require", ["signup", "login", "create_post"]))
    total_budget = float(config.get("timeouts.dynamic_total", 180))
    deadline = time.monotonic() + total_budget

    with Sandbox(app_dir, config) as box:
        if box.boot_failed:
            reason = (box.logs(tail=20) or "부팅 로그 없음").strip()[:200]
            return _boot_failed_checks(config, reason or "포트가 열리지 않음"), False, True

        ctx = pb.ProbeContext(box.base_url, config)
        checks: List[CheckResult] = []

        # functional first — it drives the gate and establishes sessions/ids.
        func_result, functional_failed = pb.probe_functional(
            ctx, dyn_cfg.get("functional", {}), require
        )
        checks.append(func_result)

        remaining = [
            ("idor_profile", pb.probe_idor_profile),
            ("access_control_admin", pb.probe_access_control_admin),
            ("stored_xss", pb.probe_stored_xss),
            ("reflected_xss", pb.probe_reflected_xss),
            ("sqli", pb.probe_sqli),
            ("transport_security", pb.probe_transport_security),
            ("rate_limiting", pb.probe_rate_limiting),
            ("weak_password_policy", pb.probe_weak_password_policy),
            ("verbose_errors", pb.probe_verbose_errors),
            ("session_forgery", pb.probe_session_forgery),
        ]
        for cid, fn in remaining:
            if time.monotonic() >= deadline:
                weight = float((dyn_cfg.get(cid, {}) or {}).get("weight", 0))
                checks.append(pb._low_conf(cid, _LABELS[cid], weight, "동적 검사 전체 시간 예산 초과"))
                continue
            checks.append(fn(ctx, dyn_cfg.get(cid, {})))

        # A03: recompute CVE against real resolved (transitive) versions.
        checks.append(_resolved_cve(box, config))

        return checks, functional_failed, False
