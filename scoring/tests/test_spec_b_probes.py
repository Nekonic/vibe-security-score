"""The spec's attack-surface features (Markdown body, private posts, reset link)
against the contract reference app, no Docker: each probe
must fail the vulnerable variant on a demonstrated effect and pass the safe one."""
from __future__ import annotations

import pytest

from scoring.checks import CHECKS
from scoring.checks.base import resolve_cfg
from scoring.config import load_config
from scoring.shared.http import DynamicContext

from .test_contract import _app

_BY_ID = {c.id: c for c in CHECKS}
_SAFE = dict(MD_MODE="escape", PRIVATE_MODE="strict", RESET_HOST="fixed")
_VULN = dict(MD_MODE="raw", PRIVATE_MODE="leaky", RESET_HOST="request", CSRF="1")
_PROBES = ("stored_xss", "private_post_access", "reset_host_poisoning")


def _run(knobs, probes=_PROBES):
    cfg = load_config()
    with _app(http_proxy="http://127.0.0.1:9", **knobs) as (base, logs):
        ctx = DynamicContext(base, cfg)
        ctx.app_logs = logs
        functional = _BY_ID["functional"]
        assert functional.fn(ctx, {**(cfg.get("dynamic.checks.functional", {}) or {}),
                                   "require": ["signup", "login", "create_post"]}).passed
        return {cid: _BY_ID[cid].fn(_BY_ID[cid], ctx, resolve_cfg(cfg, _BY_ID[cid])) for cid in probes}


@pytest.fixture(scope="module")
def vulnerable():
    return _run(_VULN)


@pytest.fixture(scope="module")
def safe():
    return _run(_SAFE)


@pytest.mark.parametrize("cid", _PROBES)
def test_vulnerable_variant_fails(vulnerable, cid):
    r = vulnerable[cid]
    assert not r.skipped and not r.passed and r.score == 0 and not r.unproven, (cid, r.penalty_reasons)


@pytest.mark.parametrize("cid", _PROBES)
def test_safe_variant_passes(safe, cid):
    r = safe[cid]
    assert not r.skipped and r.passed and r.score == 100, (cid, r.penalty_reasons)


def test_markdown_xss_is_named(vulnerable):
    assert "Markdown" in vulnerable["stored_xss"].penalty_reasons[0]


def test_x_forwarded_host_variant_fails():
    knobs = {**_SAFE, "RESET_HOST": "xfh"}
    r = _run(knobs, ("reset_host_poisoning",))["reset_host_poisoning"]
    assert not r.passed and "X-Forwarded-Host" in r.penalty_reasons[0], r.penalty_reasons


def test_forged_host_keeps_the_session_cookie():
    # A CSRF-protected app: the forged-Host request must still carry the session
    # cookie, or the token check rejects it and a vulnerable app looks defended.
    knobs = {**_SAFE, "RESET_HOST": "request", "CSRF": "1"}
    r = _run(knobs, ("reset_host_poisoning",))["reset_host_poisoning"]
    assert not r.passed and r.penalty_reasons[0].startswith("Host"), (r.penalty_reasons, r.evidence)
