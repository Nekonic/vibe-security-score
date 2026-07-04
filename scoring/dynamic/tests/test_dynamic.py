"""Integration test for the dynamic phase against the vulnerable fixture.

Boots samples/vulnerable_board in the sandbox container and asserts every
planted vuln is caught by RUNTIME probing. Skipped entirely if the ``docker``
CLI is unavailable (CI without Docker), so the suite stays green offline.
"""
from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from scoring.config import load_config
from scoring.dynamic.runner import run_dynamic

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_VULN_DIR = os.path.join(_REPO_ROOT, "samples", "vulnerable_board")


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
    checks, functional_failed, boot_failed = run_dynamic(_VULN_DIR, config)
    by_id = {c.check_id: c for c in checks}
    return by_id, functional_failed, boot_failed


def test_app_boots_and_functional_passes(dynamic_results):
    by_id, functional_failed, boot_failed = dynamic_results
    assert boot_failed is False, "vulnerable fixture should boot"
    assert functional_failed is False, "signup/login/create_post should work"
    assert by_id["functional"].passed is True
    assert by_id["functional"].score == 100.0


def test_idor_leaked(dynamic_results):
    by_id, _, _ = dynamic_results
    r = by_id["idor_profile"]
    assert r.passed is False
    assert r.score == 0.0  # score_leaked
    assert any("IDOR" in reason for reason in r.penalty_reasons)


def test_admin_exposed(dynamic_results):
    by_id, _, _ = dynamic_results
    r = by_id["access_control_admin"]
    assert r.passed is False
    assert r.score == 0.0  # score_exposed


def test_stored_xss_unescaped(dynamic_results):
    by_id, _, _ = dynamic_results
    r = by_id["stored_xss"]
    assert r.passed is False
    assert r.score == 0.0  # score_stored_unescaped


def test_sqli_injection(dynamic_results):
    by_id, _, _ = dynamic_results
    r = by_id["sqli"]
    assert r.passed is False
    assert r.score == 0.0  # score_injection
    # sqlmap is NOT installed here, so the verdict must come via the built-in
    # requests-oracle fallback (tool == "" and evidence notes the fallback path).
    assert r.tool == ""
    assert any("requests-oracle" in e for e in r.evidence)


def test_no_leftover_containers():
    proc = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=vibe-sec-dyn-", "--format", "{{.Names}}"],
        capture_output=True, text=True, timeout=20,
    )
    leftovers = [n for n in proc.stdout.splitlines() if n.strip()]
    assert leftovers == [], f"leftover containers: {leftovers}"
