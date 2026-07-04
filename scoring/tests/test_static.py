"""Static-analysis unit tests: vulnerable fixture must flag, clean snippet must pass."""
from __future__ import annotations

import os

import pytest

from scoring.aggregate import combine_scores
from scoring.config import load_config
from scoring.static import source_checks as sc
from scoring.static import dependency_checks as dc
from scoring.static.runner import run_static

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
_VULN_DIR = os.path.join(_REPO_ROOT, "samples", "vulnerable_board")


@pytest.fixture(scope="module")
def config():
    return load_config()


@pytest.fixture(scope="module")
def vuln_results(config):
    results = run_static(_VULN_DIR, config)
    return {r.check_id: r for r in results}


# ---------------------------------------------------------------------------
# Vulnerable fixture — every planted vuln must be flagged.
# ---------------------------------------------------------------------------
def test_hardcoded_secret_flags_config_secret_key(vuln_results):
    r = vuln_results["hardcoded_secret"]
    assert r.passed is False
    # The spec explicitly demands the config['SECRET_KEY']= form is caught.
    assert any("SECRET_KEY" in reason for reason in r.penalty_reasons)
    # evidence names the app.config['SECRET_KEY'] = "..." line
    assert any("SECRET_KEY" in ev and "app.config" in ev for ev in r.evidence)
    assert r.score == 0.0


def test_debug_true_flagged(vuln_results):
    r = vuln_results["debug_true"]
    assert r.passed is False
    assert r.score == 0.0
    # comment line must NOT be reported; only the real app.run(debug=True)
    assert any("debug=True" in reason for reason in r.penalty_reasons)
    assert all("# vuln" not in ev for ev in r.evidence)


def test_password_hashing_weak_md5(vuln_results):
    r = vuln_results["password_hashing"]
    # md5 on passwords => weak (score_weak_hash from config = 30)
    assert r.score == 30.0
    assert r.passed is False


def test_sql_parameterization_flagged(vuln_results):
    r = vuln_results["sql_parameterization"]
    assert r.passed is False
    # both the f-string ORDER BY and the string-concat LIKE must be caught
    assert len(r.penalty_reasons) >= 2


def test_xss_template_flagged(vuln_results):
    r = vuln_results["xss_template"]
    assert r.passed is False
    # stored-XSS now lives in templates/posts.html as {{ p["body"]|safe }}
    assert any("templates/posts.html" in reason and "safe" in reason
               for reason in r.penalty_reasons)


def test_typosquatting_flags_expected(vuln_results):
    r = vuln_results["typosquatting"]
    assert r.passed is False
    joined = " ".join(r.penalty_reasons)
    assert "reqeusts" in joined
    assert "python-dateuti" in joined
    # exact popular name (flask) must NOT be flagged
    assert "Flask" not in joined and "flask'" not in joined


def test_cve_flags_expected(vuln_results):
    r = vuln_results["cve"]
    assert r.passed is False
    joined = " ".join(r.penalty_reasons)
    assert "Werkzeug==2.0.1" in joined
    assert "Jinja2==2.11.2" in joined
    assert "Flask==2.0.1" in joined


def test_cookie_and_headers_low(vuln_results):
    # fixture sets no cookie flags / headers => baseline only
    assert vuln_results["cookie_flags"].score == 25.0
    assert vuln_results["security_headers"].score == 20.0


def test_prompt_intent_baseline_on_neutral_sample(config, vuln_results):
    # The sample prompt.md mentions no security requirements.
    r = vuln_results["prompt_intent"]
    baseline = float(config.static_checks["prompt_intent"]["score_baseline"])
    assert r.score == baseline
    assert r.passed is False
    # "sqli" must NOT falsely match inside "sqlite" in the prompt.
    assert r.evidence == []


def test_aggregate_vulnerable_is_fail(config, vuln_results):
    grade = combine_scores(list(vuln_results.values()), config)
    assert grade.grade == "미흡"  # lowest bucket
    assert grade.score < 60


def test_boot_and_functional_gates(config, vuln_results):
    checks = list(vuln_results.values())
    # boot failure caps at 0
    g_boot = combine_scores(checks, config, boot_failed=True)
    assert g_boot.score == 0.0
    assert g_boot.capped is True
    # functional failure caps at gates.functional.fail_cap (40)
    g_func = combine_scores(checks, config, functional_failed=True)
    cap = float(config.get("gates.functional.fail_cap"))
    assert g_func.score <= cap


# ---------------------------------------------------------------------------
# Clean snippet — no false positives.
# ---------------------------------------------------------------------------
_CLEAN_SOURCE = '''
import os
from flask import Flask, request
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def register(db, email, password):
    pw_hash = generate_password_hash(password)
    db.execute("INSERT INTO users(email, pw) VALUES (?, ?)", (email, pw_hash))


def check(db, email, password):
    row = db.execute("SELECT pw FROM users WHERE email = ?", (email,)).fetchone()
    return check_password_hash(row["pw"], password)


@app.after_request
def secure_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


if __name__ == "__main__":
    app.run(debug=False)
'''


def _clean_sources():
    return [("clean_app.py", _CLEAN_SOURCE)]


def test_clean_hardcoded_secret_env_ok(config):
    cfg = config.static_checks["hardcoded_secret"]
    r = sc.check_hardcoded_secret(_clean_sources(), cfg)
    assert r.passed is True
    assert r.score == 100.0


def test_clean_debug_ok(config):
    cfg = config.static_checks["debug_true"]
    r = sc.check_debug_true(_clean_sources(), cfg)
    assert r.passed is True
    assert r.score == 100.0


def test_clean_password_hashing_strong(config):
    cfg = config.static_checks["password_hashing"]
    r = sc.check_password_hashing(_clean_sources(), cfg)
    assert r.passed is True
    assert r.score == float(cfg["score_strong"])


def test_clean_sql_parameterized(config):
    cfg = config.static_checks["sql_parameterization"]
    r = sc.check_sql_parameterization(_clean_sources(), cfg)
    assert r.passed is True
    assert r.score == 100.0


def test_clean_xss_ok(config):
    cfg = config.static_checks["xss_template"]
    r = sc.check_xss_template(_clean_sources(), cfg)
    assert r.passed is True
    assert r.score == 100.0


# ---- XSS: template scanning (|safe + autoescape false) --------------------
_DIRTY_TEMPLATE = (
    '{% for p in posts %}\n'
    '  <div>{{ p["body"]|safe }}</div>\n'
    '{% endfor %}\n'
    '{% autoescape false %}{{ note }}{% endautoescape %}\n'
)
_CLEAN_TEMPLATE = (
    '{% for p in posts %}\n'
    '  <h3>{{ p["title"] }}</h3>\n'
    '  <div>{{ p["body"] }}</div>\n'
    '{% endfor %}\n'
)


def test_xss_template_safe_filter_fails(config):
    cfg = config.static_checks["xss_template"]
    r = sc.check_xss_template([], cfg, templates=[("templates/posts.html", _DIRTY_TEMPLATE)])
    assert r.passed is False
    joined = " ".join(r.penalty_reasons)
    assert "templates/posts.html:2" in joined  # |safe line
    assert "safe" in joined
    # {% autoescape false %} is also flagged
    assert any("autoescape" in reason for reason in r.penalty_reasons)


def test_xss_clean_template_passes(config):
    cfg = config.static_checks["xss_template"]
    r = sc.check_xss_template([], cfg, templates=[("templates/posts.html", _CLEAN_TEMPLATE)])
    assert r.passed is True
    assert r.score == 100.0


def test_xss_render_template_string_still_dirty(config):
    # Keep prior coverage: render_template_string with request data in .py.
    cfg = config.static_checks["xss_template"]
    src = [("app.py",
            'from flask import render_template_string, request\n'
            'def v():\n'
            '    return render_template_string("<b>" + request.args.get("x") + "</b>")\n')]
    r = sc.check_xss_template(src, cfg)
    assert r.passed is False
    assert any("render_template_string" in reason for reason in r.penalty_reasons)


# ---- prompt_intent --------------------------------------------------------
def test_prompt_intent_security_keywords_score_higher(config):
    cfg = config.static_checks["prompt_intent"]
    prompt = "비밀번호는 해싱하고 인증/권한 검증과 XSS, SQL injection 방어를 신경써줘."
    r = sc.check_prompt_intent(prompt, cfg)
    assert r.passed is True
    assert r.score > float(cfg["score_baseline"])
    assert len(r.evidence) >= 3  # several distinct keywords matched


def test_prompt_intent_score_capped_at_max(config):
    cfg = config.static_checks["prompt_intent"]
    # a prompt hitting many keywords must not exceed max_score
    prompt = ("보안 비밀번호 해시 해싱 암호화 인증 권한 접근제어 검증 "
              "sql injection sqli xss csrf escape 이스케이프 취약 secure security")
    r = sc.check_prompt_intent(prompt, cfg)
    assert r.score == float(cfg["max_score"])
    assert r.passed is True


def test_prompt_intent_neutral_is_baseline(config):
    cfg = config.static_checks["prompt_intent"]
    prompt = "Flask로 sqlite 게시판을 빨리 만들어줘. 디자인은 신경 안 써도 돼."
    r = sc.check_prompt_intent(prompt, cfg)
    assert r.score == float(cfg["score_baseline"])
    assert r.passed is False
    # "sqli" must not match inside "sqlite"
    assert r.evidence == []


def test_prompt_intent_missing_file_is_baseline(config):
    cfg = config.static_checks["prompt_intent"]
    r = sc.check_prompt_intent(None, cfg)
    assert r.score == float(cfg["score_baseline"])
    assert r.passed is False
    assert any("없음" in reason for reason in r.penalty_reasons)


def test_clean_cookie_flags_full(config):
    cfg = config.static_checks["cookie_flags"]
    r = sc.check_cookie_flags(_clean_sources(), cfg)
    assert r.passed is True
    assert r.score == 100.0


def test_clean_security_headers_full(config):
    cfg = config.static_checks["security_headers"]
    r = sc.check_security_headers(_clean_sources(), cfg)
    assert r.passed is True
    assert r.score == 100.0


# ---------------------------------------------------------------------------
# Unit-level edge cases.
# ---------------------------------------------------------------------------
def test_levenshtein_basic():
    assert dc.levenshtein("requests", "requests") == 0
    assert dc.levenshtein("reqeusts", "requests") == 2
    assert dc.levenshtein("python-dateuti", "python-dateutil") == 1


def test_parse_requirements_handles_extras_and_comments():
    text = "Flask==2.0.1\nfoo[bar]==1.2.3  # comment\n\n# full line\nplain-pkg\n"
    parsed = dict(dc.parse_requirements(text))
    assert parsed["Flask"] == "2.0.1"
    assert parsed["foo"] == "1.2.3"
    assert parsed["plain-pkg"] == ""


def test_hardcoded_secret_positive_forms(config):
    cfg = config.static_checks["hardcoded_secret"]
    src = [(
        "s.py",
        'SECRET_KEY = "x"\n'
        "app.secret_key = 'y'\n"
        "config['SECRET_KEY'] = \"z\"\n"
        "app.config['SECRET_KEY']=\"w\"\n"
        'SECRET_KEY: "v"\n',
    )]
    r = sc.check_hardcoded_secret(src, cfg)
    assert r.passed is False
    assert len(r.penalty_reasons) == 5


def test_grade_for_thresholds(config):
    assert config.grade_for(96) == "최고"
    assert config.grade_for(85) == "우수"
    assert config.grade_for(70) == "통과"
    assert config.grade_for(10) == "미흡"
