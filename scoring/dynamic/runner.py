"""Dynamic runner: boot the app in a sandbox, run the attack probes.

On boot failure every probe still yields a scored-0 CheckResult so aggregation
stays uniform — the ``boot_failed`` flag caps the final score.
"""
from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from ..config import Config
from ..models import CheckResult
from ..static import dependency_checks as dc
from ..static import tools as tools_mod
from . import probes as pb
from .container import Sandbox


@dataclass(frozen=True)
class _Probe:
    id: str
    label: str
    fn: Optional[Callable[[pb.ProbeContext, dict], CheckResult]]  # None => functional, gated inline


# functional runs first (drives the gate + seeds sessions); the rest follow in order.
_PROBES: Tuple[_Probe, ...] = (
    _Probe("functional", "기능 게이트(회원가입/로그인/글작성)", None),
    _Probe("idor_profile", "IDOR(타인 프로필 조회)", pb.probe_idor_profile),
    _Probe("access_control_admin", "접근 통제(관리자 페이지)", pb.probe_access_control_admin),
    _Probe("stored_xss", "저장형 XSS", pb.probe_stored_xss),
    _Probe("reflected_xss", "반사형 XSS", pb.probe_reflected_xss),
    _Probe("sqli", "SQL 인젝션(/search, /posts sort)", pb.probe_sqli),
    _Probe("transport_security", "전송/응답 보안(헤더·쿠키 플래그)", pb.probe_transport_security),
    _Probe("rate_limiting", "무차별 대입 방어(Rate limiting)", pb.probe_rate_limiting),
    _Probe("weak_password_policy", "비밀번호 정책", pb.probe_weak_password_policy),
    _Probe("verbose_errors", "오류 처리(스택트레이스 노출)", pb.probe_verbose_errors),
    _Probe("session_forgery", "세션 위조 검증(약한 SECRET_KEY)", pb.probe_session_forgery),
)


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
    return [
        CheckResult(
            check_id=p.id, category="dynamic", label=p.label,
            score=0.0, weight=float((dyn.get(p.id, {}) or {}).get("weight", 0)),
            passed=False,
            penalty_reasons=[f"앱 부팅 실패로 동적 검사 불가: {reason}"],
        )
        for p in _PROBES
    ]


def run_dynamic(app_dir: str, config: Config) -> Tuple[List[CheckResult], bool, bool]:
    dyn_cfg = config.get("dynamic.checks", {}) or {}
    require = list(config.get("gates.functional.require", ["signup", "login", "create_post"]))
    deadline = time.monotonic() + float(config.get("timeouts.dynamic_total", 180))

    with Sandbox(app_dir, config) as box:
        if box.boot_failed:
            reason = (box.logs(tail=20) or "부팅 로그 없음").strip()[:200]
            return _boot_failed_checks(config, reason or "포트가 열리지 않음"), False, True

        ctx = pb.ProbeContext(box.base_url, config)
        functional, rest = _PROBES[0], _PROBES[1:]

        func_result, functional_failed = pb.probe_functional(
            ctx, dyn_cfg.get(functional.id, {}), require
        )
        checks: List[CheckResult] = [func_result]

        for p in rest:
            if time.monotonic() >= deadline:
                weight = float((dyn_cfg.get(p.id, {}) or {}).get("weight", 0))
                checks.append(pb._low_conf(p.id, p.label, weight, "동적 검사 전체 시간 예산 초과"))
                continue
            checks.append(p.fn(ctx, dyn_cfg.get(p.id, {})))

        # A03: recompute CVE against real resolved (transitive) versions.
        checks.append(_resolved_cve(box, config))

        return checks, functional_failed, False
