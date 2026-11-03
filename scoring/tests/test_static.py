"""Static-analysis unit tests.

The fixture is ``samples/vulnerable_board`` (a real generated app). It gets the
injection/hashing basics right but omits several defense-in-depth controls (CSRF,
headers, cookie flags, secret hygiene, logging). Static checks run in --dev so the
suite is hermetic (no osv-scanner/semgrep/network).
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
def gen_results():
    cfg = load_config()
    cfg.dev = True
    results = run_static(_GEN_DIR, cfg)
    return {r.check_id: r for r in results}


# ---------------------------------------------------------------------------
# Real generated app — the defense-in-depth gaps must be flagged.
# ---------------------------------------------------------------------------
def test_all_expected_checks_present(gen_results):
    for cid in ("hardcoded_secret", "debug_true", "password_hashing",
                "sql_parameterization", "xss_template", "csp", "cookie_flags",
                "security_headers", "weak_default_secret",
                "insecure_deserialization", "security_logging",
                "cve", "typosquatting"):
        assert cid in gen_results, f"missing check {cid}"


def test_debug_false_not_flagged(gen_results):
    r = gen_results["debug_true"]
    assert r.passed is True and r.score == 100.0


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
    # Flask==3.0.3 is flagged by the local OSV snapshot (--dev).
    r = gen_results["cve"]
    assert r.passed is False
    joined = " ".join(r.penalty_reasons).lower()
    assert "flask==3.0.3" in joined


def test_checks_are_bucketed_by_config(gen_results):
    # Rubric category assignment happens in aggregation; run it and verify.
    from scoring.config import load_config as _lc
    grade = combine_scores(list(gen_results.values()), _lc())
    got = {c.check_id: c.category for cat in grade.categories for c in cat.checks}
    # OWASP Top 10:2025, placed by each check's mapped CWE (config/scoring.yaml).
    assert got["password_hashing"] == "A04"               # CWE-916
    assert got["hardcoded_secret"] == "reference"         # source-only key: report only
    assert got["sql_parameterization"] == "A05"
    assert got["xss_template"] == "reference"             # fixed templates decide it
    assert got["cve"] == "A03"
    assert got["security_logging"] == "reference"         # logging config: report only
    assert got["typosquatting"] == "reference"            # report only


def test_csp_missing_flagged(gen_results):
    # autoescape alone (framework default) must not earn a perfect XSS: the app
    # sets no Content-Security-Policy, so the csp defense-in-depth check fails.
    # A miss keeps partial credit (score_missing=40) since CSP is defense-in-depth,
    # not an exploit — but it still does not pass.
    r = gen_results["csp"]
    assert r.passed is False and r.score == 40.0


def test_critical_penalties_subtract_from_final(config, gen_results):
    # A confirmed SQL injection is an app takeover, so it comes straight off the final
    # score instead of being averaged. debug=False is clean. hardcoded_secret is never
    # critical: only a live session_forgery with a public weak key is.
    from scoring.models import CheckResult
    sqli = CheckResult(check_id="sqli", category="dynamic", label="SQL Injection",
                       score=0.0, weight=4.0, passed=False, penalty_reasons=["/login 인증 우회"])
    grade = combine_scores(list(gen_results.values()) + [sqli], config)
    hit = {p.check_id: p.penalty for p in grade.critical_penalties}
    assert "debug_true" not in hit
    assert "sqli" in hit
    assert "hardcoded_secret" not in hit
    assert grade.raw_score > grade.score
    assert abs((grade.raw_score - sum(hit.values())) - grade.score) < 0.01
    # Each penalty carries a severity + repro so the deduction is defensible.
    for p in grade.critical_penalties:
        assert p.severity and p.repro


def test_aggregate_runs(config, gen_results):
    grade = combine_scores(list(gen_results.values()), config)
    assert 0.0 <= grade.score <= 100.0


def test_boot_and_functional_gates(config, gen_results):
    # A synthetic all-pass result scores ~100, so the caps must actually bite.
    import dataclasses
    perfect = [dataclasses.replace(c, score=100.0, passed=True, penalty_reasons=[])
               for c in gen_results.values()]
    assert combine_scores(perfect, config).score > 90
    g_boot = combine_scores(perfect, config, boot_failed=True)
    assert g_boot.score == 0.0 and g_boot.capped is True
    g_func = combine_scores(perfect, config, functional_failed=True)
    cap = float(config.get("gates.functional.fail_cap"))
    assert g_func.capped is True and g_func.score == cap


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


# Real generated-app shapes (v2 prompt runs): allow-listed sort / fixed WHERE fragments
# concatenated with `+` while values are bound must not be flagged; spliced values must.
@pytest.mark.parametrize("query, has_params, risky", [
    ('f"SELECT p.* FROM post p JOIN user u ON u.id=p.author_id {where} ORDER BY {order}"', True, False),
    ("'select p.* from post p '+where+' order by '+order", True, False),
    ('"SELECT * FROM post ORDER BY "+orders.get(order,"p.id DESC")', True, False),
    ('"SELECT * FROM post ORDER BY "+o', False, False),
    ('"SELECT * FROM user WHERE name = \'" + name + "\'"', False, True),
    ('"SELECT * FROM post WHERE title LIKE \'%" + q + "%\'"', True, True),
    ('"SELECT * FROM post " + where', False, True),   # fragment without bound params
])
def test_sql_concatenation_structural_vs_value(query, has_params, risky):
    assert sql_ctl._is_string_built_sql(query, has_params=has_params) is risky


# ── session_timeout (static): Flask checks every cookie against
# PERMANENT_SESSION_LIFETIME (default 31 days).
from scoring.checks import A07_authentication_failures as auth_ctl  # noqa: E402


@pytest.mark.parametrize("src, score", [
    ("app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)", 100),
    ("app.config.update(PERMANENT_SESSION_LIFETIME=timedelta(hours=1))", 50),
    ("app.permanent_session_lifetime = datetime.timedelta(days=7)", 0),
    ("app.config['PERMANENT_SESSION_LIFETIME'] = 900", 100),
    ("if now - session['last_seen'] > timedelta(minutes=15): session.clear()", 100),
    ("app = Flask(__name__)", 0),
])
def test_session_timeout(config, src, score):
    r = auth_ctl.check_session_timeout(_by_id(auth_ctl, "session_timeout"),
                                       _sctx(sources=[("app.py", src)]),
                                       config.get("static.checks.session_timeout"))
    assert r.score == score and r.passed is (score == 100)


def test_sql_fragment_with_bound_params_through_real_check(config):
    # Exact v2-p0-a line: the check receives the call args WITH parentheses.
    src = [("app.py", 'def q(where, order, params):\n'
            '    return db.execute(f"SELECT p.* FROM post p JOIN user u ON u.id=p.author_id {where} ORDER BY {order}", params).fetchall()\n')]
    r = sql_ctl.check_sql_parameterization(_by_id(sql_ctl, "sql_parameterization"), _sctx(sources=src),
                                           config.get("static.checks.sql_parameterization"))
    assert r.passed is True


# Real generated-app shapes (#2, #4, #12, #19 on 2026-10-30): the base query lives in a
# variable, a helper or a parameter, and the sort comes from a literal whitelist. Every
# piece is a literal, so nothing a user sends reaches the SQL text.
_LITERAL_ONLY = {
    "base_var_plus_whitelist": (
        "def rows(sort='newest', q=None):\n"
        " order={'oldest':'p.created_at ASC','title':'p.title ASC'}.get(sort,'p.created_at DESC');"
        "sql='select p.* from post p';w=[];a=[]\n"
        " if q:w.append('(p.title like ? or p.content like ?)');a += ['%'+q+'%']*2\n"
        " if w:sql+=' where '+' and '.join(w)\n"
        " return db.execute(sql+' order by '+order,a).fetchall()\n"),
    "helper_and_parameter": (
        "def psql(): return 'SELECT p.* FROM post p'\n"
        "def posts(sql,args=(),sort='newest'):\n"
        "    order={'oldest':'p.id ASC'}.get(sort,'p.id DESC'); return db.execute(sql+' ORDER BY '+order,args)\n"
        "def search(q): return posts(psql()+' WHERE p.title LIKE ?',('%'+q+'%',))\n"
        "def home(): return posts(psql())\n"),
    "ternary_column": (
        "def posts(s):\n"
        " order={'oldest':'asc'}.get(s,'desc'); col='title' if s=='title' else 'created_at'\n"
        " return db.execute('select * from post order by '+col+' '+order).fetchall()\n"),
    # #24 on the deployed server: a private-post filter with an int() cast id.
    "int_cast_in_fstring": (
        "def sort_sql(s): return {'oldest':'p.created_at ASC'}.get(s, 'p.created_at DESC')\n"
        "def visible_clause(alias='p'):\n"
        "    u=current(); return f\" AND ({alias}.is_private=0 OR {alias}.author_id={int(u['id'])})\" if u else f\" AND {alias}.is_private=0\"\n"
        "def posts_query(where='', args=(), sort='newest'):\n"
        "    return c.execute(f\"SELECT p.* FROM post p WHERE 1=1 {where}{visible_clause()} ORDER BY {sort_sql(sort)}\", args).fetchall()\n"
        "def search(): return posts_query(' AND p.title LIKE ?', ('%q%',), 'newest')\n"),
    # #67, #69 on 2026-10-31: the private-post filter comes back with its bound values.
    "unpacked_clause_and_args": (
        "def visible_clause():\n"
        "    u=current(); return (' AND (p.is_private=0 OR p.author_id=?)', (u['id'],)) if u else (' AND p.is_private=0', ())\n"
        "def posts():\n"
        "    order={'oldest':'p.id ASC'}.get(request.args.get('sort'),'p.id DESC'); cl,args=visible_clause()\n"
        "    return db.execute('SELECT p.* FROM post p WHERE 1=1'+cl+' ORDER BY '+order,args).fetchall()\n"),
}
_USER_VALUE = {
    "route_parameter": "@app.get('/u/<n>')\ndef u(n):\n    return db.execute(\"SELECT * FROM user WHERE name='\"+n+\"'\")\n",
    "request_arg": ("def s():\n    o=request.args.get('sort','id')\n    sql='select * from post'\n"
                    "    return db.execute(sql+' order by '+o+' desc')\n"),
    "caller_passes_input": ("def rows(w):\n    return db.execute('select * from post '+w)\n"
                            "def v():\n    return rows(request.args['q'])\n"),
    "appended_input": ("def s(q):\n    w=[]\n    w.append(q)\n    sql='select * from post where '+' and '.join(w)\n"
                       "    return db.execute(sql+' order by id', ())\n"),
    "str_not_int": ("def s():\n    u=request.args['u']\n    return db.execute(f\"select * from post where author={str(u)}\")\n"),
    "unpacked_input": ("def pick():\n    return (request.args['w'], ())\n"
                       "def s():\n    w,a=pick()\n    return db.execute('select * from post where '+w, a)\n"),
    "dict_of_inputs": ("def s():\n    m={'a':request.args['x']}\n    sql='select 1 '\n"
                       "    return db.execute(sql+m.get('a','id'))\n"),
}


@pytest.mark.parametrize("name", sorted(_LITERAL_ONLY))
def test_sql_built_only_from_literals_passes(config, name):
    r = sql_ctl.check_sql_parameterization(_by_id(sql_ctl, "sql_parameterization"),
                                           _sctx(sources=[("app.py", _LITERAL_ONLY[name])]),
                                           config.get("static.checks.sql_parameterization"))
    assert r.passed is True, r.evidence


@pytest.mark.parametrize("name", sorted(_USER_VALUE))
def test_sql_carrying_a_user_value_still_fails(config, name):
    r = sql_ctl.check_sql_parameterization(_by_id(sql_ctl, "sql_parameterization"),
                                           _sctx(sources=[("app.py", _USER_VALUE[name])]),
                                           config.get("static.checks.sql_parameterization"))
    assert r.passed is False


@pytest.mark.parametrize("code, expected", [
    # werkzeug and a per-user random salt: strong
    ("from werkzeug.security import generate_password_hash\nh = generate_password_hash(password)", "score_strong"),
    ("import hashlib, secrets\ndef hp(p):\n    s = secrets.token_bytes(16)\n"
     "    return s.hex() + ':' + hashlib.scrypt(p.encode(), salt=s, n=16384, r=8, p=1).hex()\n"
     "def ok(p, h):\n    s, x = h.split(':')\n"
     "    return hashlib.scrypt(p.encode(), salt=bytes.fromhex(s), n=16384, r=8, p=1).hex() == x", "score_strong"),
    ("import hashlib, secrets\nsalt = secrets.token_bytes(16)\n"
     "dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 260000)", "score_strong"),
    # one salt for every user, or too few iterations: weak KDF
    ("import hashlib\ndef pw(v): return hashlib.scrypt(v.encode(), salt=app.secret_key.encode()[:16], n=16384, r=8, p=1).hex()",
     "score_weak_kdf"),
    ("import hashlib\ndef hash_pw(p): return hashlib.pbkdf2_hmac('sha256', p.encode(), app.secret_key.encode(), 180000).hex()",
     "score_weak_kdf"),
    ("import hashlib\nSALT = b'fixed'\ndef hash_pw(p): return hashlib.pbkdf2_hmac('sha256', p.encode(), SALT, 260000).hex()",
     "score_weak_kdf"),
    ("import hashlib, os\ndef hash_pw(p):\n    salt = os.urandom(16)\n"
     "    return hashlib.pbkdf2_hmac('sha256', p.encode(), salt, 1000).hex()", "score_weak_kdf"),
    # fast hashes: salted beats unsalted; SECRET_KEY is not a salt
    ("import hashlib, secrets\ndef hash_pw(p):\n    salt = secrets.token_hex(8)\n"
     "    return salt + hashlib.sha256((salt + p).encode()).hexdigest()", "score_salted_fast_hash"),
    ("import hashlib\ndef password_hash(p): return hashlib.sha256(p.encode()).hexdigest()", "score_weak_hash"),
    ("import hashlib\ndef hashpw(p): return hashlib.sha256((app.secret_key + p).encode()).hexdigest()", "score_weak_hash"),
    # an OTP code hashed with a secrets.* value is not a password hash
    ("import hashlib, secrets\nfrom werkzeug.security import generate_password_hash\n"
     "c = f'{secrets.randbelow(1000000):06d}'; session['vc'] = hashlib.sha256(c.encode()).hexdigest()\n"
     "h = generate_password_hash(password)", "score_strong"),
    # a reset token hashed on a line that prints the /password/reset link
    ("import hashlib, secrets\nfrom werkzeug.security import generate_password_hash\n"
     "t=secrets.token_urlsafe(32);c.execute('INSERT INTO reset VALUES(?)',(hashlib.sha256(t.encode()).hexdigest(),));"
     "print('RESET LINK: http://127.0.0.1:5000/password/reset?token='+t)\n"
     "h = generate_password_hash(password)", "score_strong"),
    ("import hashlib\nfrom werkzeug.security import generate_password_hash\n"
     "c.execute('UPDATE user SET password=? WHERE id=?',(generate_password_hash(pw),uid)); "
     "c.execute('DELETE FROM reset_token WHERE token_hash=?',(hashlib.sha256(tok.encode()).hexdigest(),))",
     "score_strong"),
    ("import hashlib\nh = hashlib.sha256(row['password'].encode()).hexdigest()", "score_weak_hash"),
    # the password is named only by the SQL that stores the hash
    ("import hashlib\n"
     "db.execute('UPDATE users SET password=? WHERE id=?', (hashlib.sha256(new.encode()).hexdigest(), uid))",
     "score_weak_hash"),
    ("import hashlib\n"
     "db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (u, hashlib.md5(x.encode()).hexdigest()))",
     "score_weak_hash"),
    ("import hashlib\nfrom werkzeug.security import generate_password_hash\n"
     "db.execute('INSERT INTO password_resets (token_hash) VALUES (?)', (hashlib.sha256(t.encode()).hexdigest(),))\n"
     "h = generate_password_hash(password)", "score_strong"),
])
def test_password_hashing_salt_levels(config, code, expected):
    cfg = config.static_checks["password_hashing"]
    r = crypto.check_password_hashing(_by_id(crypto, "password_hashing"),
                                      _sctx(sources=[("app.py", code)]), cfg)
    assert r.score == float(cfg[expected]), (r.score, r.penalty_reasons)


@pytest.mark.parametrize("dotenv, flagged", [
    ('SECRET_KEY=board-secret-2026-fixed\n', True),
    ('# local\nexport FLASK_SECRET_KEY="quoted value"\n', True),
    ('SECRET_KEY=\nDATABASE=app.db\n', False),   # empty: the app must get it elsewhere
    ('DATABASE=app.db\n', False),
])
def test_hardcoded_secret_reads_the_shipped_dotenv(config, tmp_path, dotenv, flagged):
    # The sandbox loads the harvested .env into the environment, so a key there is a
    # key in the source.
    (tmp_path / ".env").write_text(dotenv, encoding="utf-8")
    src = [("app.py", "import os\napp.secret_key = os.environ['SECRET_KEY']\n")]
    cfg = config.static_checks["hardcoded_secret"]
    r = crypto.check_hardcoded_secret(_by_id(crypto, "hardcoded_secret"),
                                      _sctx(src, app_dir=str(tmp_path), config=config), cfg)
    assert r.passed is (not flagged), r.penalty_reasons
    assert not any("board-secret" in e for e in r.evidence)  # the value is not echoed


def test_hardcoded_secret_without_an_app_dir_reads_no_dotenv(config, tmp_path, monkeypatch):
    # An empty app_dir must not fall back to the process's working directory.
    (tmp_path / ".env").write_text("SECRET_KEY=from-cwd\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    src = [("app.py", "import os\napp.secret_key = os.environ['SECRET_KEY']\n")]
    r = crypto.check_hardcoded_secret(_by_id(crypto, "hardcoded_secret"), _sctx(src, config=config),
                                      config.static_checks["hardcoded_secret"])
    assert r.passed is True, r.penalty_reasons
