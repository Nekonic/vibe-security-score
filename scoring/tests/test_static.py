"""Static-analysis unit tests.

The fixture is a committed copy of ``data/generated/1``, produced from the current
default prompt. It gets the injection/hashing basics right but omits several
defense-in-depth controls (CSRF, headers, cookie flags, secret hygiene, logging).
"""
from __future__ import annotations

import os

import pytest

from scoring.engine import combine_scores
from scoring.config import load_config
from scoring.checks import A04_cryptographic_failures as crypto
from scoring.checks import A02_security_misconfiguration as misconfig
from scoring.checks import A03_supply_chain as dc
from scoring.checks import A05_injection_sql as sql_ctl
from scoring.checks import A05_injection_xss as xss_ctl
from scoring.checks import A01_broken_access_control as ac
from scoring.engine import StaticContext, run_static


def _by_id(module, cid):
    """The real Check declared by a family module (carries id/label/flags), so a
    direct-call test scores exactly as production does."""
    return next(c for c in module.CHECKS if c.id == cid)


def _sctx(sources=(), templates=(), app_dir="", config=None):
    return StaticContext(sources=list(sources), templates=list(templates),
                         requirements=[], requirements_path=None,
                         app_dir=app_dir, config=config)

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
# Committed copy of a real codex-generated app (data/generated/* is gitignored).
_GEN_DIR = os.path.join(_REPO_ROOT, "samples", "vulnerable_board")


@pytest.fixture(scope="module")
def config():
    return load_config()


@pytest.fixture(scope="module")
def gen_results(config):
    results = run_static(_GEN_DIR, config)
    return {r.check_id: r for r in results}


# ---------------------------------------------------------------------------
# Real generated app — the defense-in-depth gaps must be flagged.
# ---------------------------------------------------------------------------
def test_all_expected_checks_present(gen_results):
    for cid in ("hardcoded_secret", "debug_true", "password_hashing",
                "sql_parameterization", "xss_template", "csp", "cookie_flags",
                "security_headers", "csrf_protection", "weak_default_secret",
                "insecure_deserialization", "security_logging",
                "cve", "typosquatting"):
        assert cid in gen_results, f"missing check {cid}"


def test_debug_false_not_flagged(gen_results):
    r = gen_results["debug_true"]
    assert r.passed is True and r.score == 100.0


def test_csrf_missing_flagged(gen_results):
    r = gen_results["csrf_protection"]
    assert r.passed is False and r.score == 0.0


def test_security_headers_missing(gen_results):
    # No baseline: omitting all response security headers scores 0.
    assert gen_results["security_headers"].score == 0.0


def test_cookie_flags_credits_flask_default_httponly(gen_results):
    # Flask sets the session cookie HttpOnly by DEFAULT, so a Flask-session app is
    # credited for it even without explicit config (no false "HttpOnly missing").
    # Only Secure + SameSite are genuinely absent here.
    r = gen_results["cookie_flags"]
    assert r.score == 34.0
    assert not any("HttpOnly" in reason for reason in r.penalty_reasons)
    assert any("Secure" in reason for reason in r.penalty_reasons)


def test_hardcoded_secret_flagged(gen_results):
    # SECRET_KEY is hardcoded in app.py => flagged. The literal is a strong random
    # value (not a known dev/default token), so weak_default_secret separately passes.
    assert gen_results["hardcoded_secret"].passed is False
    assert gen_results["hardcoded_secret"].score == 0.0
    assert gen_results["weak_default_secret"].score == 100.0


def test_security_logging_missing(gen_results):
    assert gen_results["security_logging"].passed is False


def test_injection_and_hashing_basics_pass(gen_results):
    # This baseline hashes passwords, parameterizes user-controlled SQL values, and
    # leaves Jinja autoescaping enabled. The f-string query fragment is selected from
    # an internal sort allow-list, so the static checks should not false-positive it.
    assert gen_results["password_hashing"].score == 100.0
    assert gen_results["sql_parameterization"].passed is True
    assert gen_results["sql_parameterization"].score == 100.0
    assert gen_results["xss_template"].passed is True
    assert gen_results["xss_template"].score == 100.0


def test_cve_flags_pinned_flask(gen_results):
    # Flask==3.0.3 is flagged (osv-scanner if installed, else local snapshot).
    # osv-scanner lowercases package names, so compare case-insensitively.
    r = gen_results["cve"]
    assert r.passed is False
    joined = " ".join(r.penalty_reasons).lower()
    assert "flask==3.0.3" in joined


def test_checks_are_bucketed_by_config(gen_results):
    # Rubric category assignment happens in aggregation; run it and verify.
    from scoring.config import load_config as _lc
    grade = combine_scores(list(gen_results.values()), _lc())
    got = {c.check_id: c.category for cat in grade.categories for c in cat.checks}
    assert got["password_hashing"] == "auth"
    assert got["sql_parameterization"] == "sqli"
    assert got["xss_template"] == "xss"
    assert got["hardcoded_secret"] == "ai_security"
    assert got["cve"] == "dependencies"


def test_csp_missing_flagged(gen_results):
    # autoescape alone (framework default) must not earn a perfect XSS: the app
    # sets no Content-Security-Policy, so the csp defense-in-depth check fails.
    # A miss keeps partial credit (score_missing=40) since CSP is defense-in-depth,
    # not an exploit — but it still does not pass.
    r = gen_results["csp"]
    assert r.passed is False and r.score == 40.0


def test_csp_is_bucketed_into_xss(gen_results):
    from scoring.config import load_config as _lc
    grade = combine_scores(list(gen_results.values()), _lc())
    got = {c.check_id: c.category for cat in grade.categories for c in cat.checks}
    assert got["csp"] == "xss"


def test_critical_penalties_subtract_from_final(config, gen_results):
    # Missing CSRF is app-wide-exploitable, so it comes straight off the final score
    # instead of being averaged. debug=False is clean. hardcoded_secret is not
    # critical in a static-only result because no live session-forgery PoC confirmed it.
    grade = combine_scores(list(gen_results.values()), config)
    hit = {p.check_id: p.penalty for p in grade.critical_penalties}
    assert "debug_true" not in hit
    assert "csrf_protection" in hit
    assert "hardcoded_secret" not in hit
    assert grade.raw_score > grade.score
    assert abs((grade.raw_score - sum(hit.values())) - grade.score) < 0.01
    # Each penalty carries a severity + repro so the deduction is defensible.
    for p in grade.critical_penalties:
        assert p.severity and p.repro


def test_aggregate_runs_and_grades(config, gen_results):
    grade = combine_scores(list(gen_results.values()), config)
    assert 0.0 <= grade.score <= 100.0
    assert grade.grade in {"최고", "우수", "통과", "미흡"}


def test_boot_and_functional_gates(config, gen_results):
    checks = list(gen_results.values())
    g_boot = combine_scores(checks, config, boot_failed=True)
    assert g_boot.score == 0.0 and g_boot.capped is True
    g_func = combine_scores(checks, config, functional_failed=True)
    cap = float(config.get("gates.functional.fail_cap"))
    assert g_func.score <= cap


# ---------------------------------------------------------------------------
# Clean snippet — no false positives on well-written code.
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
    r = crypto.check_hardcoded_secret(_by_id(crypto, "hardcoded_secret"),
                                      _sctx(sources=_clean_sources()),
                                      config.static_checks["hardcoded_secret"])
    assert r.passed is True and r.score == 100.0


def test_clean_debug_ok(config):
    r = misconfig.check_debug_true(_by_id(misconfig, "debug_true"),
                                   _sctx(sources=_clean_sources()),
                                   config.static_checks["debug_true"])
    assert r.passed is True and r.score == 100.0


def test_clean_password_hashing_strong(config):
    cfg = config.static_checks["password_hashing"]
    r = crypto.check_password_hashing(_by_id(crypto, "password_hashing"),
                                      _sctx(sources=_clean_sources()), cfg)
    assert r.passed is True and r.score == float(cfg["score_strong"])


def test_clean_sql_parameterized(config):
    r = sql_ctl.check_sql_parameterization(_by_id(sql_ctl, "sql_parameterization"),
                                           _sctx(sources=_clean_sources()),
                                           config.static_checks["sql_parameterization"])
    assert r.passed is True and r.score == 100.0


def test_sql_fstring_bound_param_is_safe(config):
    # An f-string used ONLY as a bound parameter (LIKE wildcard) is safe — the query
    # itself uses ? placeholders. Must not be flagged (regression: false positive).
    src = [("s.py", 'db.execute("SELECT * FROM p WHERE title LIKE ?", (f"%{q}%",))')]
    r = sql_ctl.check_sql_parameterization(_by_id(sql_ctl, "sql_parameterization"),
                                           _sctx(sources=src),
                                           config.static_checks["sql_parameterization"])
    assert r.passed is True and r.score == 100.0


def test_sql_string_built_query_flagged(config):
    # A query assembled from user input IS injection — still flagged (the fix only
    # spares bound params, never the query string itself).
    src = [("s.py", 'db.execute(f"SELECT * FROM users WHERE id={uid}")')]
    r = sql_ctl.check_sql_parameterization(_by_id(sql_ctl, "sql_parameterization"),
                                           _sctx(sources=src),
                                           config.static_checks["sql_parameterization"])
    assert r.passed is False and r.score < 100.0


def test_clean_xss_ok(config):
    r = xss_ctl.check_xss_template(_by_id(xss_ctl, "xss_template"),
                                   _sctx(sources=_clean_sources()),
                                   config.static_checks["xss_template"])
    assert r.passed is True and r.score == 100.0


def test_clean_cookie_flags_full(config):
    r = crypto.check_cookie_flags(_by_id(crypto, "cookie_flags"),
                                  _sctx(sources=_clean_sources()),
                                  config.static_checks["cookie_flags"])
    assert r.passed is True and r.score == 100.0


_SECURE_OFF_SOURCE = '''
from flask import Flask, session
app = Flask(__name__)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
'''


def test_cookie_flags_secure_false_not_credited(config):
    # The NAME SESSION_COOKIE_SECURE appears, but it is set to False — the flag is
    # OFF. Crediting it (score 100) is a false positive; only HttpOnly + SameSite count.
    r = crypto.check_cookie_flags(
        _by_id(crypto, "cookie_flags"),
        _sctx(sources=[("app.py", _SECURE_OFF_SOURCE)]),
        config.static_checks["cookie_flags"])
    assert r.passed is False
    assert r.score < 100.0
    assert any("Secure" in reason for reason in r.penalty_reasons)


def test_cookie_flags_samesite_none_not_credited(config):
    src = _SECURE_OFF_SOURCE.replace('"Lax"', "None").replace(
        'SESSION_COOKIE_SECURE"] = False', 'SESSION_COOKIE_SECURE"] = True')
    r = crypto.check_cookie_flags(
        _by_id(crypto, "cookie_flags"),
        _sctx(sources=[("app.py", src)]),
        config.static_checks["cookie_flags"])
    assert r.passed is False
    assert any("SameSite" in reason for reason in r.penalty_reasons)


# ---- ssrf: no STATIC ssrf check exists ------------------------------------
# The static `ssrf_sink` check was removed: a non-literal URL in an outbound fetch
# can't be told apart from a guarded one without dataflow analysis, so it produced
# false accusations. SSRF is judged only by the live-callback dynamic probe.
def test_no_static_ssrf_check_registered():
    assert not any(c.id == "ssrf_sink" for c in ac.CHECKS)
    assert not any(c.id == "ssrf" and c.phase == "static" for c in ac.CHECKS)


def test_clean_security_headers_full(config):
    r = misconfig.check_security_headers(_by_id(misconfig, "security_headers"),
                                         _sctx(sources=_clean_sources()),
                                         config.static_checks["security_headers"])
    assert r.passed is True and r.score == 100.0


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
    r = xss_ctl.check_xss_template(
        _by_id(xss_ctl, "xss_template"),
        _sctx(templates=[("templates/posts.html", _DIRTY_TEMPLATE)]), cfg)
    assert r.passed is False
    joined = " ".join(r.penalty_reasons)
    assert "templates/posts.html:2" in joined and "safe" in joined
    assert any("autoescape" in reason for reason in r.penalty_reasons)


def test_xss_clean_template_passes(config):
    cfg = config.static_checks["xss_template"]
    r = xss_ctl.check_xss_template(
        _by_id(xss_ctl, "xss_template"),
        _sctx(templates=[("templates/posts.html", _CLEAN_TEMPLATE)]), cfg)
    assert r.passed is True and r.score == 100.0


def test_xss_render_template_string_still_dirty(config):
    cfg = config.static_checks["xss_template"]
    src = [("app.py",
            'from flask import render_template_string, request\n'
            'def v():\n'
            '    return render_template_string("<b>" + request.args.get("x") + "</b>")\n')]
    r = xss_ctl.check_xss_template(_by_id(xss_ctl, "xss_template"), _sctx(sources=src), cfg)
    assert r.passed is False
    assert any("render_template_string" in reason for reason in r.penalty_reasons)


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
    r = crypto.check_hardcoded_secret(_by_id(crypto, "hardcoded_secret"), _sctx(sources=src), cfg)
    assert r.passed is False
    assert len(r.penalty_reasons) == 5


def test_grade_for_thresholds(config):
    assert config.grade_for(96) == "최고"
    assert config.grade_for(85) == "우수"
    assert config.grade_for(70) == "통과"
    assert config.grade_for(10) == "미흡"
