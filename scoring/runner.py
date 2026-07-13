"""Runners: gather inputs and execute every registered control by phase.

The static phase is offline; the dynamic phase boots the app in a sandbox and
attacks it over real HTTP. Both derive their check list from ``scoring.registry``.
On boot failure every dynamic probe still yields a scored-0 CheckResult so
aggregation stays uniform — the ``boot_failed`` flag caps the final score.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import List, Optional

from . import registry
from .config import Config
from .controls import dependencies
from .models import CheckResult
from .shared.http import ProbeContext, _low_conf
from .shared.sandbox import Sandbox
from .shared.sources import Source, _read_tree

_PY_EXT = ".py"
_HTML_EXTS = (".html", ".htm", ".jinja", ".jinja2", ".j2")
_REQ_NAMES = ("requirements.txt",)
_TEMPLATES_DIRNAME = "templates"


# --- static -----------------------------------------------------------------
@dataclass(frozen=True)
class StaticContext:
    sources: List[Source]
    templates: List[Source]
    requirements: list
    requirements_path: Optional[str]
    app_dir: str
    config: Config


def _gather_sources(app_dir: str) -> List[Source]:
    return _read_tree(app_dir, app_dir, lambda fn: fn.endswith(_PY_EXT))


def _gather_templates(app_dir: str) -> List[Source]:
    tpl_dir = os.path.join(app_dir, _TEMPLATES_DIRNAME)
    return _read_tree(tpl_dir, app_dir, lambda fn: fn.lower().endswith(_HTML_EXTS))


def _requirements_path(app_dir: str) -> Optional[str]:
    for name in _REQ_NAMES:
        path = os.path.join(app_dir, name)
        if os.path.isfile(path):
            return path
    return None


def _read_requirements(app_dir: str) -> str:
    path = _requirements_path(app_dir)
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return ""


def run_static(app_dir: str, config: Config) -> List[CheckResult]:
    sctx = StaticContext(
        sources=_gather_sources(app_dir),
        templates=_gather_templates(app_dir),
        requirements=dependencies.parse_requirements(_read_requirements(app_dir)),
        requirements_path=_requirements_path(app_dir),
        app_dir=app_dir,
        config=config,
    )
    checks_cfg = config.static_checks
    return [c.fn(sctx, checks_cfg.get(c.id, {})) for c in registry.by_phase("static")]


# --- dynamic ----------------------------------------------------------------
def _boot_failed_checks(config: Config, reason: str) -> List[CheckResult]:
    dyn = config.get("dynamic.checks", {}) or {}
    return [
        CheckResult(
            check_id=c.id, category="dynamic", label=c.label,
            score=0.0, weight=float((dyn.get(c.id, {}) or {}).get("weight", 0)),
            passed=False,
            penalty_reasons=[f"앱 부팅 실패로 동적 검사 불가: {reason}"],
        )
        for c in registry.by_phase("dynamic")
    ]


def run_dynamic(app_dir: str, config: Config):
    dyn_cfg = config.get("dynamic.checks", {}) or {}
    require = list(config.get("gates.functional.require", ["signup", "login", "create_post"]))
    deadline = time.monotonic() + float(config.get("timeouts.dynamic_total", 180))

    with Sandbox(app_dir, config) as box:
        if box.boot_failed:
            reason = (box.logs(tail=20) or "부팅 로그 없음").strip()[:200]
            return _boot_failed_checks(config, reason or "포트가 열리지 않음"), False, True

        ctx = ProbeContext(box.base_url, config)
        dynamic_controls = registry.by_phase("dynamic")
        # functional runs first (drives the gate + seeds sessions); rest follow.
        functional = next(c for c in dynamic_controls if c.id == "functional")
        rest = [c for c in dynamic_controls if c.id != "functional"]

        func_result, functional_failed = functional.fn(
            ctx, dyn_cfg.get(functional.id, {}), require
        )
        checks: List[CheckResult] = [func_result]

        for c in rest:
            if time.monotonic() >= deadline:
                weight = float((dyn_cfg.get(c.id, {}) or {}).get("weight", 0))
                checks.append(_low_conf(c.id, c.label, weight, "동적 검사 전체 시간 예산 초과"))
                continue
            checks.append(c.fn(ctx, dyn_cfg.get(c.id, {})))

        # A03: recompute CVE against real resolved (transitive) versions.
        checks.append(dependencies.resolved_cve(box, config))

        return checks, functional_failed, False
