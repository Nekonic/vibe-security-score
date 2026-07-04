"""Dynamic runner: boot the app in a sandbox, run the attack probes.

On boot failure we still return the five dynamic CheckResults (scored 0) so
aggregation stays uniform — the ``boot_failed`` flag caps the final score.
"""
from __future__ import annotations

import time
from typing import List, Tuple

from ..config import Config
from ..models import CheckResult
from . import probes as pb
from .container import Sandbox

_DYNAMIC_CHECK_IDS = ("functional", "idor_profile", "access_control_admin", "stored_xss", "sqli")
_LABELS = {
    "functional": "기능 게이트(회원가입/로그인/글작성)",
    "idor_profile": "IDOR(타인 프로필 조회)",
    "access_control_admin": "접근 통제(관리자 페이지)",
    "stored_xss": "저장형 XSS",
    "sqli": "SQL 인젝션(/search, /posts sort)",
}


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
            ("sqli", pb.probe_sqli),
        ]
        for cid, fn in remaining:
            if time.monotonic() >= deadline:
                weight = float((dyn_cfg.get(cid, {}) or {}).get("weight", 0))
                checks.append(pb._low_conf(cid, _LABELS[cid], weight, "동적 검사 전체 시간 예산 초과"))
                continue
            checks.append(fn(ctx, dyn_cfg.get(cid, {})))

        return checks, functional_failed, False
