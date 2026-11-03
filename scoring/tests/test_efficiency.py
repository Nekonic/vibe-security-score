"""Prompt efficiency: final = security × multiplier(participant prompt chars)."""
import copy

import pytest

from scoring.config import Config, load_config
from scoring.engine import efficiency


@pytest.fixture
def cfg():
    raw = copy.deepcopy(load_config().raw)
    raw["efficiency"] = {"enabled": True, "free_chars": 200, "min_multiplier": 0.8}
    raw.setdefault("submission", {})["max_prompt_chars"] = 1000
    return Config(raw)


@pytest.mark.parametrize("chars, expected", [
    (0, 1.0), (19, 1.0), (200, 1.0), (600, 0.9), (1000, 0.8), (5000, 0.8)])
def test_multiplier_is_flat_then_linear_to_the_floor(cfg, chars, expected):
    assert efficiency.multiplier(chars, cfg) == pytest.approx(expected)


def test_shorter_prompt_with_same_security_ranks_higher(cfg):
    long_ = efficiency.apply({"final_score": 90.0}, 900, cfg)
    short = efficiency.apply({"final_score": 90.0}, 300, cfg)
    assert short["final_score"] > long_["final_score"]
    assert short["security_score"] == long_["security_score"] == 90.0


def test_short_prompt_with_no_security_gains_nothing(cfg):
    assert efficiency.apply({"final_score": 3.0}, 19, cfg)["final_score"] == 3.0


def test_final_score_is_the_adjusted_score(cfg):
    r = efficiency.apply({"final_score": 62.0, "boot_failed": False, "functional_failed": False}, 1000, cfg)
    assert r["final_score"] == pytest.approx(49.6)
    assert "grade" not in r and "pass_fail" not in r


def test_disabled_leaves_report_as_graded(cfg):
    report = {"final_score": 80.0}
    cfg.raw["efficiency"]["enabled"] = False
    assert efficiency.apply(report, 900, cfg) == report
