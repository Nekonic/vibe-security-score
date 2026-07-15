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
from .checks import A03_supply_chain as dependencies
from .models import CheckResult
from .shared.http import DynamicContext, _scored_zero
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


def run_static(app_dir: str, config: Config, on_check=None) -> List[CheckResult]:
    sctx = StaticContext(
        sources=_gather_sources(app_dir),
        templates=_gather_templates(app_dir),
        requirements=dependencies.parse_requirements(_read_requirements(app_dir)),
        requirements_path=_requirements_path(app_dir),
        app_dir=app_dir,
        config=config,
    )
    checks_cfg = config.static_checks
    results: List[CheckResult] = []
    for c in registry.by_phase("static"):
        results.append(c.fn(sctx, checks_cfg.get(c.id, {})))
        if on_check:
            on_check(c.label)  # progress tick
    return results


# --- dynamic ----------------------------------------------------------------
def _boot_failed_checks(config: Config, reason: str) -> List[CheckResult]:
    dyn = config.get("dynamic.checks", {}) or {}
    # skipped=True (NOT passed=False): the app never booted, so NOTHING was actually
    # tested. Marking these "failed" would (a) falsely accuse the app of SQLi/XSS/
    # IDOR/etc. on the result page and (b) trigger every dynamic critical penalty for
    # untested defects. skipped => excluded from aggregation AND critical penalties;
    # the boot-fail gate cap (gates.boot.fail_cap) is what actually bounds the score.
    return [
        CheckResult(
            check_id=c.id, category="dynamic", label=c.label,
            score=0.0, weight=float((dyn.get(c.id, {}) or {}).get("weight", 0)),
            passed=False,
            skipped=True,
            penalty_reasons=[f"앱 부팅 실패로 동적 검사 불가: {reason}"],
        )
        for c in registry.by_phase("dynamic")
    ]


def run_dynamic(app_dir: str, config: Config, on_check=None):
    """Returns (checks, functional_failed, boot_failed, boot_log). boot_log is the
    container's log tail on boot failure (empty otherwise) so the operator sees WHY."""
    dyn_cfg = config.get("dynamic.checks", {}) or {}
    require = list(config.get("gates.functional.require", ["signup", "login", "create_post"]))
    deadline = time.monotonic() + float(config.get("timeouts.dynamic_total", 180))

    with Sandbox(app_dir, config) as box:
        if box.boot_failed:
            boot_log = (box.logs(tail=60) or "부팅 로그 없음").strip()
            short = (boot_log.splitlines()[-1] if boot_log else "포트가 열리지 않음")[:200]
            return _boot_failed_checks(config, short), False, True, boot_log

        ctx = DynamicContext(box.base_url, config)
        # Feed hardcoded SECRET_KEY literals to session_forgery so it forges with the
        # app's ACTUAL key (a live PoC proving a hardcoded secret is exploitable).
        from .checks.A04_cryptographic_failures import extract_hardcoded_secrets
        ctx.source_secrets = extract_hardcoded_secrets(_gather_sources(app_dir))
        dynamic_checks = registry.by_phase("dynamic")
        # functional runs first (drives the gate + seeds sessions); rest follow.
        functional = next(c for c in dynamic_checks if c.id == "functional")
        rest = [c for c in dynamic_checks if c.id != "functional"]

        func_result = functional.fn(ctx, {**dyn_cfg.get(functional.id, {}), "require": require})
        functional_failed = not func_result.passed
        checks: List[CheckResult] = [func_result]
        if on_check:
            on_check(functional.label)

        for c in rest:
            if time.monotonic() >= deadline:
                weight = float((dyn_cfg.get(c.id, {}) or {}).get("weight", 0))
                checks.append(_scored_zero(c.id, c.label, weight, "동적 검사 전체 시간 예산 초과"))
            else:
                checks.append(c.fn(ctx, dyn_cfg.get(c.id, {})))
            if on_check:
                on_check(c.label)

        # A03: recompute CVE against real resolved (transitive) versions.
        checks.append(dependencies.dynamic_cve(box, config))
        if on_check:
            on_check("의존성 CVE 재검사")

        return checks, functional_failed, False, ""
