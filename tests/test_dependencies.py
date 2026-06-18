"""Regression tests for modules/dependencies.py."""
import os
import pytest

import config
from modules import dependencies
from modules.dependencies import _levenshtein


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _findings_by_id(result):
    return {f["id"]: f for f in result["findings"]}


# ---------------------------------------------------------------------------
# Unit: Levenshtein helper
# ---------------------------------------------------------------------------

class TestLevenshtein:
    def test_identical_strings_zero(self):
        assert _levenshtein("flask", "flask") == 0

    def test_requsts_to_requests_is_1(self):
        # 'requsts' is missing the 'e' in 'requests'
        assert _levenshtein("requsts", "requests") == 1

    def test_flsk_to_flask_is_1(self):
        assert _levenshtein("flsk", "flask") == 1

    def test_empty_strings(self):
        assert _levenshtein("", "") == 0

    def test_one_empty(self):
        assert _levenshtein("abc", "") == 3
        assert _levenshtein("", "abc") == 3

    def test_known_distance_two(self):
        # 'nzmpz' vs 'numpy': two substitutions (u->z, y->z) => distance 2
        assert _levenshtein("nzmpz", "numpy") == 2
        # 'requsts' vs 'requests' is a single insertion => distance 1
        assert _levenshtein("requsts", "requests") == 1


# ---------------------------------------------------------------------------
# Integration: typosquat fixture (requirements with 'flsk' and 'requsts')
# Kept separate from samples/insecure_app so that app stays pip-installable and
# runnable for the functional gate; this fixture is a deliberately bad lockfile.
# ---------------------------------------------------------------------------

class TestTyposquatDeps:
    @pytest.fixture(autouse=True)
    def run(self, repo_root):
        fixture = os.path.join(repo_root, "tests", "fixtures", "typosquat_app")
        self.result = dependencies.analyze(fixture)
        self.findings = _findings_by_id(self.result)

    def test_flsk_is_flagged(self):
        assert "typosquat_flsk" in self.findings, (
            "Expected 'flsk' to be flagged as a potential typosquat"
        )
        assert self.findings["typosquat_flsk"]["passed"] is False

    def test_requsts_is_flagged(self):
        assert "typosquat_requsts" in self.findings, (
            "Expected 'requsts' to be flagged as a potential typosquat"
        )
        assert self.findings["typosquat_requsts"]["passed"] is False

    def test_flask_not_flagged(self):
        # 'flask' is an exact popular-package match — must not appear in typosquat findings
        assert "typosquat_flask" not in self.findings

    def test_werkzeug_not_flagged(self):
        assert "typosquat_werkzeug" not in self.findings

    def test_jinja2_not_flagged(self):
        assert "typosquat_jinja2" not in self.findings

    def test_osv_finding_is_skipped(self):
        # osv-scanner is not present in this test environment
        cve = self.findings.get("cve_scan")
        if cve is not None:
            assert cve.get("skipped") is True, (
                "CVE scan finding should be skipped when osv-scanner is absent"
            )

    def test_score_equals_100_minus_two_typosquat_penalties(self):
        expected = config.DEPENDENCIES_START - 2 * config.TYPOSQUAT_PENALTY
        assert self.result["score"] == pytest.approx(expected, abs=0.1), (
            f"Expected score {expected}, got {self.result['score']}"
        )


# ---------------------------------------------------------------------------
# Integration: secure_app (no typosquat packages)
# ---------------------------------------------------------------------------

class TestSecureAppDeps:
    @pytest.fixture(autouse=True)
    def run(self, samples_dir):
        secure = os.path.join(samples_dir, "secure_app")
        self.result = dependencies.analyze(secure)
        self.findings = _findings_by_id(self.result)

    def test_no_typosquat_findings(self):
        typosquat_findings = [
            f for f in self.result["findings"]
            if f["id"].startswith("typosquat_") and f["passed"] is False
        ]
        assert typosquat_findings == [], (
            f"Unexpected typosquat findings: {typosquat_findings}"
        )

    def test_score_is_100_ignoring_cve(self):
        # In the absence of osv-scanner the CVE check is skipped (score-neutral).
        # Typosquat should add no penalty, so score == 100.
        assert self.result["score"] == pytest.approx(100.0, abs=0.1)


# ---------------------------------------------------------------------------
# Unit: missing requirements.txt returns score 100 with a skipped finding
# ---------------------------------------------------------------------------

def test_missing_requirements_returns_neutral_score(tmp_path):
    result = dependencies.analyze(str(tmp_path))
    assert result["score"] == float(config.DEPENDENCIES_START)
    findings = _findings_by_id(result)
    assert "requirements_missing" in findings
    assert findings["requirements_missing"].get("skipped") is True
