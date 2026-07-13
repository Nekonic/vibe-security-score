"""Integration test for the dynamic phase against a REAL codex-generated app.

Boots data/generated/7 in the sandbox container and asserts the pipeline drives
it end-to-end: the app boots, the functional gate passes, defended controls score
high (no false positives), and the defense-in-depth gaps a basic app omits are
detected. Skipped entirely if the ``docker`` CLI/daemon is unavailable.
"""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from scoring.config import load_config
from scoring.runner import run_dynamic

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
# Committed copy of a real codex-generated app (data/generated/* is gitignored).
_APP_DIR = os.path.join(_REPO_ROOT, "samples", "vulnerable_board")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        proc = subprocess.run(
            ["docker", "info"], capture_output=True, text=True, timeout=20
        )
        return proc.returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_available(), reason="docker CLI/daemon unavailable"
)


@pytest.fixture(scope="module")
def dynamic_results():
    config = load_config()
    checks, functional_failed, boot_failed = run_dynamic(_APP_DIR, config)
    by_id = {c.check_id: c for c in checks}
    return by_id, functional_failed, boot_failed


def test_app_boots_and_functional_passes(dynamic_results):
    by_id, functional_failed, boot_failed = dynamic_results
    assert boot_failed is False, "generated app should boot"
    assert functional_failed is False, "signup/login/create_post should work"
    assert by_id["functional"].passed is True
    assert by_id["functional"].score == 100.0


def test_injection_defenses_not_false_flagged(dynamic_results):
    # The app parameterizes SQL and autoescapes templates => probes must NOT
    # falsely report injection/XSS (score stays high).
    by_id, _, _ = dynamic_results
    assert by_id["sqli"].score == 100.0
    assert by_id["stored_xss"].score == 100.0
    assert by_id["reflected_xss"].score == 100.0


def test_sqli_uses_builtin_oracle_without_dev(dynamic_results):
    # sqlmap is dev-gated (and not installed) => verdict comes from the built-in
    # oracle, not the sqlmap CLI (tool stays empty).
    by_id, _, _ = dynamic_results
    assert by_id["sqli"].tool == ""


def test_defense_in_depth_gaps_detected(dynamic_results):
    # A basic app omits these controls => the new probes must flag them.
    by_id, _, _ = dynamic_results
    assert by_id["transport_security"].score == 0.0   # no security headers/cookie flags
    assert by_id["rate_limiting"].score == 0.0        # no brute-force throttling
    assert by_id["weak_password_policy"].score == 0.0 # accepts a trivial password


def test_session_forgery_live_poc(dynamic_results):
    # The app falls back to a hardcoded SECRET_KEY, so a forged Flask session
    # cookie (user_id=1 => the seeded admin) must reach /admin. This is the live
    # evidence behind the weak_default_secret critical penalty. Skipped if flask
    # isn't importable on the host (report-only weight-0 check).
    by_id, _, _ = dynamic_results
    r = by_id["session_forgery"]
    if r.skipped:
        pytest.skip("flask not importable on host — no live forge")
    assert r.passed is False and r.score == 0.0
    assert any("위조" in reason for reason in r.penalty_reasons)
    assert any("forged" in ev for ev in r.evidence)


def test_resolved_cve_flags_pinned_flask(dynamic_results):
    by_id, _, _ = dynamic_results
    r = by_id["cve"]
    assert "freeze" in r.tool  # resolved (pip-freeze) path
    assert any("flask" in reason.lower() for reason in r.penalty_reasons)


def test_no_leftover_containers():
    proc = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=vibe-sec-dyn-", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=20,
    )
    leftovers = [n for n in proc.stdout.splitlines() if n.strip()]
    assert leftovers == [], f"leftover containers: {leftovers}"
