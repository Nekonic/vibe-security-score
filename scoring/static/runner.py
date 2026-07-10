"""Static runner: gather sources + requirements, run every static check. Offline."""
from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..config import Config
from ..models import CheckResult
from . import source_checks as sc
from . import owasp_checks as oc
from . import dependency_checks as dc
from . import tools as tools_mod

_PY_EXT = ".py"
_HTML_EXTS = (".html", ".htm", ".jinja", ".jinja2", ".j2")
_REQ_NAMES = ("requirements.txt",)
_TEMPLATES_DIRNAME = "templates"


def _read_tree(root: str, base: str, match) -> List[Tuple[str, str]]:
    """Collect (relpath, text) for files under ``root`` whose name passes ``match``,
    with relpaths relative to ``base``."""
    out: List[Tuple[str, str]] = []
    if not os.path.isdir(root):
        return out
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if not match(fn):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, base).replace(os.sep, "/")
            try:
                with open(full, "r", encoding="utf-8", errors="replace") as fh:
                    out.append((rel, fh.read()))
            except OSError:
                continue
    return out


def _gather_sources(app_dir: str) -> List[Tuple[str, str]]:
    return _read_tree(app_dir, app_dir, lambda fn: fn.endswith(_PY_EXT))


def _gather_templates(app_dir: str) -> List[Tuple[str, str]]:
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


def _read_prompt(app_dir: str, filename: str) -> Optional[str]:
    path = os.path.join(app_dir, filename)
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    return None


def run_static(app_dir: str, config: Config) -> List[CheckResult]:
    sources = _gather_sources(app_dir)
    templates = _gather_templates(app_dir)
    checks_cfg = config.static_checks
    dep_cfg = dict(config.static_dependencies)

    results: List[CheckResult] = []

    results.append(sc.check_hardcoded_secret(sources, checks_cfg.get("hardcoded_secret", {})))
    results.append(sc.check_debug_true(sources, checks_cfg.get("debug_true", {})))
    results.append(sc.check_password_hashing(sources, checks_cfg.get("password_hashing", {})))
    results.append(sc.check_sql_parameterization(sources, checks_cfg.get("sql_parameterization", {})))
    results.append(sc.check_xss_template(sources, checks_cfg.get("xss_template", {}), templates))
    results.append(sc.check_cookie_flags(sources, checks_cfg.get("cookie_flags", {})))
    results.append(sc.check_security_headers(sources, checks_cfg.get("security_headers", {})))

    # OWASP defense-in-depth controls (must be demonstrated, not merely absent-of-bug).
    results.append(oc.check_csrf_protection(sources, checks_cfg.get("csrf_protection", {}), templates))
    results.append(oc.check_csp(sources, checks_cfg.get("csp", {}), templates))
    results.append(oc.check_weak_default_secret(sources, checks_cfg.get("weak_default_secret", {})))
    results.append(oc.check_insecure_deserialization(sources, checks_cfg.get("insecure_deserialization", {})))
    results.append(oc.check_security_logging(sources, checks_cfg.get("security_logging", {})))
    results.append(oc.check_ssrf_sink(sources, checks_cfg.get("ssrf_sink", {})))

    # dependencies.weight is split across cve + typosquatting by their explicit
    # sub-weights (typosquatting is a smaller share; edit distance can false-flag).
    req_text = _read_requirements(app_dir)
    requirements = dc.parse_requirements(req_text)

    dep_weight = float(dep_cfg.get("weight", 0))
    cve_cfg = dict(dep_cfg)
    cve_cfg["weight"] = float((dep_cfg.get("cve") or {}).get("weight", dep_weight / 2.0))
    typo_cfg = dict(dep_cfg)
    typo_cfg["weight"] = float((dep_cfg.get("typosquatting") or {}).get("weight", dep_weight / 2.0))

    # CVE: OSV-Scanner primary (if installed+enabled) with local-snapshot fallback.
    req_path = _requirements_path(app_dir)
    results.append(
        tools_mod.check_cve_with_osv(requirements, cve_cfg, req_path, config)
    )
    results.append(dc.check_typosquatting(requirements, typo_cfg))

    # Optional external tools: gitleaks + semgrep report-only (weight 0), pypi opt-in.
    results.append(tools_mod.check_gitleaks(app_dir, config))
    results.append(tools_mod.check_semgrep(app_dir, config))
    results.append(tools_mod.check_pypi_existence(requirements, config))

    return results
