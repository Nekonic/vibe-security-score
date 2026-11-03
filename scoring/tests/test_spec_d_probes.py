"""Spec-D probes (open_redirect, csv_injection, reset_enumeration, otp_bruteforce,
reset_token_leak) and the account probes (otp_bypass, stale_session_reuse)
against two fixture apps that differ only in those decisions: spec_d_vuln must fail
every probe, spec_d_safe must pass every one. Docker integration (~30s per app)."""
from __future__ import annotations

import os

import pytest

from scoring.checks import CHECKS
from scoring.checks.base import resolve_cfg
from scoring.config import load_config
from scoring.shared.http import DynamicContext
from scoring.shared.sandbox import Sandbox

from .test_ground_truth import _docker_available

pytestmark = pytest.mark.skipif(not _docker_available(), reason="docker CLI/daemon unavailable")

_APPS = os.path.join(os.path.dirname(__file__), "fixtures", "apps")
_PROBES = ("open_redirect", "csv_injection", "reset_token_leak", "otp_bypass", "stale_session_reuse",
           "reset_enumeration", "otp_bruteforce")


def _run(app: str):
    cfg = load_config()
    by_id = {c.id: c for c in CHECKS}
    with Sandbox(os.path.join(_APPS, app), cfg) as box:
        assert not box.boot_failed, box.logs(30)
        ctx = DynamicContext(box.base_url, cfg)
        ctx.app_logs = lambda: box.logs(tail=2000)
        functional = by_id["functional"]
        assert functional.fn(ctx, {**(cfg.get("dynamic.checks.functional", {}) or {}),
                                   "require": ["signup", "login", "create_post"]}).passed
        return {cid: by_id[cid].fn(by_id[cid], ctx, resolve_cfg(cfg, by_id[cid])) for cid in _PROBES}


def test_vulnerable_fixture_fails_every_probe():
    for cid, r in _run("spec_d_vuln").items():
        assert not r.skipped and not r.passed and r.score == 0, (cid, r.penalty_reasons)


def test_safe_fixture_passes_every_probe():
    for cid, r in _run("spec_d_safe").items():
        assert not r.skipped and r.passed and r.score == 100, (cid, r.penalty_reasons)
