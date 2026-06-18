"""Regression tests for modules/secure_coding.py."""
import os
import pytest

import config
from modules import secure_coding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _findings_by_id(result):
    return {f["id"]: f for f in result["findings"]}


# ---------------------------------------------------------------------------
# Integration: insecure_app — should score 0 with all 8 checks failing
# ---------------------------------------------------------------------------

class TestInsecureApp:
    @pytest.fixture(autouse=True)
    def run(self, samples_dir):
        insecure = os.path.join(samples_dir, "insecure_app")
        self.result = secure_coding.analyze(insecure)
        self.findings = _findings_by_id(self.result)

    def test_score_is_zero(self):
        assert self.result["score"] == 0.0

    def test_all_eight_checks_fail(self):
        for check_id in config.SECURE_CODING_PENALTIES:
            f = self.findings.get(check_id)
            assert f is not None, f"Finding '{check_id}' missing from results"
            assert f["passed"] is False, (
                f"Expected '{check_id}' to FAIL on insecure_app, but it passed"
            )

    def test_findings_count_matches_penalties(self):
        assert len(self.result["findings"]) == len(config.SECURE_CODING_PENALTIES)


# ---------------------------------------------------------------------------
# Integration: secure_app — should score 100 with all 8 checks passing
# ---------------------------------------------------------------------------

class TestSecureApp:
    @pytest.fixture(autouse=True)
    def run(self, samples_dir):
        secure = os.path.join(samples_dir, "secure_app")
        self.result = secure_coding.analyze(secure)
        self.findings = _findings_by_id(self.result)

    def test_score_is_100(self):
        assert self.result["score"] == 100.0

    def test_all_eight_checks_pass(self):
        for check_id in config.SECURE_CODING_PENALTIES:
            f = self.findings.get(check_id)
            assert f is not None, f"Finding '{check_id}' missing from results"
            assert f["passed"] is True, (
                f"Expected '{check_id}' to PASS on secure_app, but it failed"
            )


# ---------------------------------------------------------------------------
# Unit: env-sourced secret key must NOT trigger hardcoded_secret
# ---------------------------------------------------------------------------

def test_env_sourced_secret_passes(tmp_path):
    """app.py using os.environ.get for SECRET_KEY should PASS the hardcoded_secret check."""
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "app.secret_key = os.environ.get('SECRET_KEY', 'fallback')\n",
        encoding="utf-8",
    )
    result = secure_coding.analyze(str(tmp_path))
    findings = _findings_by_id(result)
    assert findings["hardcoded_secret"]["passed"] is True, (
        "os.environ.get should not be flagged as a hardcoded secret"
    )


# ---------------------------------------------------------------------------
# Unit: penalties are applied in the expected amounts
# ---------------------------------------------------------------------------

def test_penalty_values_match_config(samples_dir):
    """Each failing finding should carry exactly the penalty value from config."""
    insecure = os.path.join(samples_dir, "insecure_app")
    result = secure_coding.analyze(insecure)
    findings = _findings_by_id(result)
    for check_id, expected_penalty in config.SECURE_CODING_PENALTIES.items():
        f = findings[check_id]
        if not f["passed"]:
            assert f["penalty"] == float(expected_penalty), (
                f"'{check_id}' penalty expected {expected_penalty}, "
                f"got {f['penalty']}"
            )


# ---------------------------------------------------------------------------
# Unit: score is floored at 0 (not negative)
# ---------------------------------------------------------------------------

def test_score_never_negative(tmp_path):
    """Even a maximally insecure file must produce score >= 0."""
    app_py = tmp_path / "app.py"
    # Pile many bad patterns in one file
    app_py.write_text(
        "from flask import Flask\n"
        "import hashlib\n"
        "app = Flask(__name__)\n"
        "app.secret_key = 'hardcoded'\n"
        "app.run(debug=True)\n",
        encoding="utf-8",
    )
    result = secure_coding.analyze(str(tmp_path))
    assert result["score"] >= 0.0
