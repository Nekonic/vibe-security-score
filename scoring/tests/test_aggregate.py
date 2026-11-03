"""Aggregation rules (scoring/engine/aggregate.py) on synthetic results — the score
math every grading depends on: skip-not-zero, weight-0 categories, critical tiers
and their conditions, and the gate caps."""
from __future__ import annotations

import pytest

from scoring.config import load_config
from scoring.engine import combine_scores
from scoring.models import CheckResult


@pytest.fixture(scope="module")
def config():
    return load_config()


_CFG = load_config()


def _weight(cid):
    """The check's configured weight, as the real check would report it."""
    for path in (f"dynamic.checks.{cid}.weight", f"static.checks.{cid}.weight",
                 f"static.dependencies.{cid}.weight"):
        w = _CFG.get(path)
        if w is not None:
            return float(w)
    return 0.0


def _r(cid, score=100.0, passed=True, skipped=False, weight=None, evidence=None):
    return CheckResult(check_id=cid, category="", label=cid, score=score,
                       weight=_weight(cid) if weight is None else weight, passed=passed,
                       skipped=skipped, evidence=list(evidence or []))


def _all_pass():
    ids = ["idor_profile", "access_control_admin", "admin_user_mgmt", "privilege_escalation",
           "sqli", "sql_parameterization", "stored_xss", "reflected_xss", "xss_template",
           "unrestricted_upload", "csrf_protection", "ssrf", "insecure_deserialization",
           "password_hashing", "weak_default_secret", "hardcoded_secret", "cookie_flags",
           "rate_limiting", "weak_password_policy", "default_credentials",
           "auth_session_management", "verbose_errors", "debug_true", "cve",
           "security_headers", "csp", "security_logging", "functional",
           "otp_bypass", "stale_session_reuse"]
    return {cid: _r(cid) for cid in ids}


def _replace(results, **changed):
    out = dict(results)
    out.update(changed)
    return list(out.values())


def test_all_pass_scores_100(config):
    assert combine_scores(list(_all_pass().values()), config).score == pytest.approx(100.0)


def test_skipped_check_neither_scores_zero_nor_triggers_critical(config):
    base = _all_pass()
    g = combine_scores(_replace(base, idor_profile=_r("idor_profile", 0.0, False, skipped=True)), config)
    assert g.score == pytest.approx(100.0)
    assert not g.critical_penalties


def test_reference_and_functional_categories_never_move_the_score(config):
    base = _all_pass()
    extra = [_r("typosquatting", 0.0, False), _r("transport_security", 0.0, False),
             _r("semgrep", 0.0, False, weight=0.0)]
    g = combine_scores(_replace(base, functional=_r("functional", 0.0, False)) + extra, config)
    assert g.raw_score == pytest.approx(100.0)


def test_failed_critical_subtracts_from_final(config):
    g = combine_scores(_replace(_all_pass(), sqli=_r("sqli", 0.0, False)), config)
    pen = {p.check_id: p.penalty for p in g.critical_penalties}
    assert pen == {"sqli": 25.0}
    assert g.score == pytest.approx(g.raw_score - 25.0)
    assert all(p.severity and p.repro for p in g.critical_penalties)


@pytest.mark.parametrize("cid", ["ssrf", "csrf_protection", "stored_xss", "unrestricted_upload",
                                 "idor_profile", "password_hashing", "otp_bypass",
                                 "stale_session_reuse"])
def test_non_takeover_failures_cost_category_points_only(config, cid):
    # Only attack-proven takeovers are critical; these lower their category instead.
    g = combine_scores(_replace(_all_pass(), **{cid: _r(cid, 0.0, False)}), config)
    assert g.critical_penalties == []
    assert g.score == pytest.approx(g.raw_score) and g.raw_score < 100


@pytest.mark.parametrize("cid", ["debug_true", "verbose_errors", "reflected_xss", "xss_template"])
def test_checks_the_spec_decides_are_reference(config, cid):
    # The fixed spec or templates already decide these: every app passes them, so they
    # sit in reference with weight 0 and a failure moves nothing.
    g = combine_scores(_replace(_all_pass(), **{cid: _r(cid, 0.0, False)}), config)
    assert g.raw_score == pytest.approx(100.0) and g.critical_penalties == []
    assert config.category_map[cid] == "reference"


@pytest.mark.parametrize("cid, pts", [("sqli", 25.0), ("privilege_escalation", 25.0),
                                      ("default_credentials", 25.0),
                                      ("access_control_admin", 15.0), ("admin_user_mgmt", 15.0)])
def test_weight_zero_critical_keeps_its_penalty(config, cid, pts):
    # Moved to reference with weight 0: no category points, the proven takeover still
    # comes off the final score.
    assert config.category_map[cid] == "reference" and _weight(cid) == 0
    g = combine_scores(_replace(_all_pass(), **{cid: _r(cid, 0.0, False)}), config)
    assert g.raw_score == pytest.approx(100.0)
    assert [(p.check_id, p.penalty) for p in g.critical_penalties] == [(cid, pts)]
    assert g.score == pytest.approx(100.0 - pts)


@pytest.mark.parametrize("cid", ["hardcoded_secret", "weak_default_secret"])
def test_secret_seen_only_in_source_costs_nothing(config, cid):
    # A key the source reveals is not guessable from outside: reference only.
    g = combine_scores(_replace(_all_pass(), **{cid: _r(cid, 0.0, False)}), config)
    assert g.critical_penalties == []
    assert g.raw_score == pytest.approx(100.0)


def test_proven_session_forgery_is_the_critical(config):
    forged = _r("session_forgery", 0.0, False, evidence=["forged session -> /admin 200"])
    secrets = {cid: _r(cid, 0.0, False) for cid in ("hardcoded_secret", "weak_default_secret")}
    g = combine_scores(_replace(_all_pass(), **secrets) + [forged], config)
    pen = {p.check_id: p for p in g.critical_penalties}
    assert set(pen) == {"session_forgery"}
    assert pen["session_forgery"].penalty == 25.0
    assert pen["session_forgery"].severity and pen["session_forgery"].repro
    assert any("forged" in e for e in pen["session_forgery"].evidence)
    assert g.raw_score == pytest.approx(100.0)     # weight 0: critical only
    assert g.score == pytest.approx(75.0)


def test_skipped_session_forgery_is_no_critical(config):
    skipped = _r("session_forgery", 0.0, False, skipped=True)
    g = combine_scores(_replace(_all_pass()) + [skipped], config)
    assert g.critical_penalties == []


@pytest.mark.parametrize("cid", ["csp", "security_headers", "cookie_flags",
                                 "security_logging", "session_timeout"])
def test_unexploitable_config_costs_nothing(config, cid):
    g = combine_scores(_replace(_all_pass(), **{cid: _r(cid, 0.0, False)}), config)
    assert g.raw_score == pytest.approx(100.0) and g.critical_penalties == []
    assert config.category_map[cid] == "reference"


def test_category_without_weighted_checks_is_not_scored(config):
    # A09 lost its only check. Its config weight is 0 and it gets no result row;
    # a category holding only weight-0 checks must not average them into a score.
    assert config.get("categories.A09.weight") == 0
    g = combine_scores(_replace(_all_pass(), security_logging=_r("security_logging", 0.0, False)), config)
    assert "A09" not in {cat.name for cat in g.categories}
    raw = dict(config.raw)
    ref = dict(raw["categories"]["reference"])
    ref["checks"] = [c for c in ref["checks"] if c != "security_logging"]
    raw["categories"] = dict(raw["categories"], reference=ref,
                             A09={"weight": 3.5, "label": "A09", "checks": ["security_logging"]})
    from scoring.config import Config
    stale = Config(raw)                    # weight left behind on a 0-weight check
    g = combine_scores(_replace(_all_pass(), security_logging=_r("security_logging", 0.0, False)), stale)
    a09 = next(cat for cat in g.categories if cat.name == "A09")
    assert all(c.category_weight == 0 for c in a09.checks)
    assert g.raw_score == pytest.approx(100.0)


def test_nothing_weighted_scores_zero_not_a_bogus_average(config):
    g = combine_scores([_r("csp", 100.0, True), _r("security_logging", 100.0, True)], config)
    assert g.raw_score == 0.0


def test_medium_and_low_cve_cost_nothing(config):
    assert float(config.get("static.dependencies.cve.penalty_medium")) == 0
    assert float(config.get("static.dependencies.cve.penalty_low")) == 0
    assert float(config.get("static.dependencies.cve.penalty_high")) > 0
    from scoring.checks.A03_supply_chain import _match_cve
    dep = dict(config.static_dependencies)
    medium = _match_cve([("Jinja2", "3.1.2")], dep)          # CVE-2024-22195 medium only
    assert medium.score == 100.0 and medium.passed is True
    assert any("CVE-2024-22195" in r for r in medium.penalty_reasons)   # still listed
    high = _match_cve([("Werkzeug", "3.0.2")], dep)          # high + medium
    assert high.score == 75.0 and high.passed is False


def test_functional_gate_caps_and_boot_zeroes(config):
    results = list(_all_pass().values())
    cap = float(config.get("gates.functional.fail_cap"))
    g = combine_scores(results, config, functional_failed=True)
    assert g.capped and g.score == cap
    g = combine_scores(results, config, boot_failed=True)
    assert g.capped and g.score == 0.0
