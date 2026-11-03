"""Tests for external-tool integrations (scoring/shared/external_tools.py).

Non-dev: a missing/disabled required tool aborts at preflight (never a silent fallback).
--dev SKIP path: tools absent/disabled => skipped, deterministic score unchanged.
PARSE path: stub binary emits canned JSON => assert parse -> CheckResult mapping.
"""
from __future__ import annotations

import copy
import os

import pytest

from scoring.config import Config, load_config
from scoring.checks import A04_cryptographic_failures as crypto
from scoring.checks import A03_supply_chain as dependencies
from scoring.checks import sast
from scoring.checks.A03_supply_chain import parse_requirements
from scoring.engine import StaticContext

_HERE = os.path.dirname(__file__)
_STUBS = os.path.join(_HERE, "stubs")
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, "..", ".."))
_APP_DIR = os.path.join(_REPO_ROOT, "samples", "vulnerable_board")  # committed codex app copy


def _stub(name: str) -> str:
    return os.path.join(_STUBS, name)


def _by_id(module, cid):
    """The real Check declared by a family module (carries id/label/flags), so a
    direct-call test scores exactly as production does."""
    return next(c for c in module.CHECKS if c.id == cid)


def _sctx(app_dir: str, config: Config) -> StaticContext:
    return StaticContext(sources=[], templates=[], requirements=[],
                         requirements_path=None, app_dir=app_dir, config=config)


@pytest.fixture(scope="module")
def base_config():
    return load_config()


def _config_with_tool(base: Config, tool: str, **overrides) -> Config:
    """Return a Config copy with tools.<tool> patched by ``overrides``. Default
    (non-dev) mode: installed tools run, missing tools skip/fallback."""
    raw = copy.deepcopy(base.raw)
    raw.setdefault("tools", {}).setdefault(tool, {}).update(overrides)
    return Config(raw)


# ---------------------------------------------------------------------------
# SKIP path (no binaries present / disabled)
# ---------------------------------------------------------------------------
def test_missing_tools_abort_preflight_outside_dev(base_config):
    # Default (non-dev) mode: a missing enabled tool or a disabled sqlmap must be
    # reported so grading aborts BEFORE scoring — never a silent fallback.
    from scoring.shared.external_tools import missing_required_tools

    cfg = _config_with_tool(base_config, "gitleaks", enabled=True, binary="definitely-not-here-xyz")
    cfg.dev = False
    assert "definitely-not-here-xyz" in missing_required_tools(cfg)
    cfg = _config_with_tool(base_config, "sqlmap", enabled=False)
    cfg.dev = False
    assert any(m.endswith("(비활성화)") for m in missing_required_tools(cfg))
    cfg.dev = True
    assert missing_required_tools(cfg) == []


def test_gitleaks_skipped_in_dev_when_binary_missing(base_config):
    cfg = _config_with_tool(base_config, "gitleaks", enabled=True, binary="definitely-not-here-xyz")
    cfg.dev = True
    r = crypto.check_gitleaks_secrets(_by_id(crypto, "gitleaks_secrets"), _sctx(_APP_DIR, cfg), {})
    assert r.skipped is True
    assert r.weight == 0.0
    assert r.tool == "gitleaks"
    assert "검사 생략" in r.penalty_reasons[0]


def test_semgrep_skipped_when_disabled(base_config):
    cfg = _config_with_tool(base_config, "semgrep", enabled=False)
    r = sast.check_semgrep(_by_id(sast, "semgrep"), _sctx(_APP_DIR, cfg), {})
    assert r.skipped is True
    assert r.weight == 0.0
    assert r.tool == "semgrep"


def test_osv_uses_local_snapshot_in_dev(base_config):
    """--dev: the built-in snapshot replaces osv-scanner (tool == "")."""
    cfg = _config_with_tool(base_config, "osv_scanner", enabled=True, binary="no-such-osv-bin")
    cfg.dev = True
    dep_cfg = dict(base_config.static_dependencies)
    dep_cfg["weight"] = float(dep_cfg.get("weight", 0)) / 2.0
    reqs = parse_requirements(open(os.path.join(_APP_DIR, "requirements.txt"), encoding="utf-8").read())
    req_path = os.path.join(_APP_DIR, "requirements.txt")
    r = dependencies.check_cve(reqs, dep_cfg, req_path, cfg)
    assert r.check_id == "cve"
    assert r.tool == ""              # fallback path, not the CLI
    # Sample pins Flask==3.0.3 (one HIGH, -25) in the snapshot => 100 - 25.
    assert r.score == 75.0
    assert any("Flask==3.0.3" in reason for reason in r.penalty_reasons)


# ---------------------------------------------------------------------------
# PARSE path (stub binaries emitting canned JSON)
# ---------------------------------------------------------------------------
def test_osv_stub_applies_critical_penalty(base_config):
    cfg = _config_with_tool(base_config, "osv_scanner", enabled=True, binary=_stub("osv_scanner_stub.py"))
    dep_cfg = dict(base_config.static_dependencies)
    dep_cfg["weight"] = float(dep_cfg.get("weight", 0)) / 2.0
    penalty_critical = float(base_config.get("static.dependencies.cve.penalty_critical"))

    req_path = os.path.join(_APP_DIR, "requirements.txt")
    reqs = parse_requirements(open(req_path, encoding="utf-8").read())
    r = dependencies.check_cve(reqs, dep_cfg, req_path, cfg)

    assert r.tool == "osv-scanner"   # CLI path was used
    assert r.check_id == "cve"
    # one CRITICAL vuln from the stub => 100 - penalty_critical
    assert r.score == max(0.0, 100.0 - penalty_critical)
    assert any("OSV-STUB-CRITICAL" in reason and "critical" in reason
               for reason in r.penalty_reasons)


def test_gitleaks_stub_surfaces_secret(base_config):
    cfg = _config_with_tool(base_config, "gitleaks", enabled=True, binary=_stub("gitleaks_stub.py"))
    r = crypto.check_gitleaks_secrets(_by_id(crypto, "gitleaks_secrets"), _sctx(_APP_DIR, cfg), {})
    assert r.skipped is False
    assert r.weight == 0.0           # report-only, never moves the score
    assert r.tool == "gitleaks"
    assert r.passed is False
    joined = " ".join(r.penalty_reasons)
    assert "app.py:23" in joined
    assert "generic-api-key" in joined


def test_semgrep_stub_surfaces_finding(base_config):
    cfg = _config_with_tool(base_config, "semgrep", enabled=True, binary=_stub("semgrep_stub.py"))
    r = sast.check_semgrep(_by_id(sast, "semgrep"), _sctx(_APP_DIR, cfg), {})
    assert r.skipped is False
    assert r.weight == 0.0
    assert r.tool == "semgrep"
    assert r.passed is False
    joined = " ".join(r.penalty_reasons)
    assert "app.py:156" in joined
    assert "debug-enabled" in joined


def test_osv_stub_does_not_change_report_only_semantics(base_config):
    """Even when the OSV CLI path is used, the cve check keeps its real weight
    (it is NOT report-only) — this guards against accidentally zeroing it."""
    cfg = _config_with_tool(base_config, "osv_scanner", enabled=True, binary=_stub("osv_scanner_stub.py"))
    dep_cfg = dict(base_config.static_dependencies)
    dep_cfg["weight"] = 5.0
    req_path = os.path.join(_APP_DIR, "requirements.txt")
    reqs = parse_requirements(open(req_path, encoding="utf-8").read())
    r = dependencies.check_cve(reqs, dep_cfg, req_path, cfg)
    assert r.weight == 5.0


def test_osv_alias_ids_count_as_one_vulnerability():
    # osv-scanner (online) lists one flaw under its GHSA id and again under the
    # PYSEC alias; penalising both would double-count one CVE.
    pkg = {"package": {"name": "urllib3", "version": "1.23"}, "vulnerabilities": [
        {"id": "GHSA-wqvq-5m8c-6g24", "aliases": ["CVE-2020-26137", "PYSEC-2020-148"]},
        {"id": "PYSEC-2020-148", "aliases": ["CVE-2020-26137", "GHSA-wqvq-5m8c-6g24"]},
    ]}
    found = dependencies._parse_osv_output({"results": [{"packages": [pkg]}]})
    assert [f[2] for f in found] == ["GHSA-wqvq-5m8c-6g24"]
