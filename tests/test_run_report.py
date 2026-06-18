"""Regression tests for the orchestrator (run.py) and report.py scoring math."""
import config
import report
import run


# --------------------------------------------------------------------------- #
# report.grade_for — grade bands from config                                    #
# --------------------------------------------------------------------------- #

def test_grade_bands():
    assert report.grade_for(95) == "A"
    assert report.grade_for(85) == "B"
    assert report.grade_for(75) == "C"
    assert report.grade_for(65) == "D"
    assert report.grade_for(50) == "F"
    # Exact boundaries land on the band.
    assert report.grade_for(90) == "A"
    assert report.grade_for(config.PASS_THRESHOLD) == "C"


# --------------------------------------------------------------------------- #
# report.build_result — weighting + gate cap                                    #
# --------------------------------------------------------------------------- #

def _all_100(gate_passed):
    return {
        "secure_coding": {"score": 100, "findings": []},
        "dependencies": {"score": 100, "findings": []},
        "prompt_quality": {"score": 100, "findings": []},
        "functional": {"score": 100, "gate_passed": gate_passed, "findings": []},
    }


def test_build_result_perfect_and_gate_passed():
    res = report.build_result(_all_100(gate_passed=True), prompt_provided=True)
    # sum of weights == 1.0, all sub-scores 100 => 100
    assert res["final_score"] == 100.0
    assert res["gate_passed"] is True
    assert res["gate_capped"] is False
    assert res["passed"] is True
    assert res["grade"] == "A"


def test_build_result_gate_failure_caps_final():
    # High static scores but functional gate failed => capped.
    mods = {
        "secure_coding": {"score": 100, "findings": []},
        "dependencies": {"score": 100, "findings": []},
        "prompt_quality": {"score": 100, "findings": []},
        "functional": {"score": 0, "gate_passed": False, "findings": []},
    }
    res = report.build_result(mods, prompt_provided=True)
    assert res["final_score"] == config.FUNCTIONAL_GATE_CAP
    assert res["gate_capped"] is True
    assert res["passed"] is False  # gate failed => never PASS


def test_weights_sum_to_one():
    assert abs(sum(config.MODULE_WEIGHTS.values()) - 1.0) < 1e-9


# --------------------------------------------------------------------------- #
# run._safe — a crashing module degrades instead of sinking the run             #
# --------------------------------------------------------------------------- #

def test_safe_traps_exceptions():
    def boom(*_a):
        raise RuntimeError("kaboom")

    out = run._safe("boom_mod", boom, "x")
    assert out["score"] == 0.0
    assert out["findings"] and out["findings"][0].get("skipped") is True


def test_safe_sets_default_gate():
    def boom(*_a):
        raise ValueError("nope")

    out = run._safe("functional", boom, "x", default_gate=False)
    assert out["gate_passed"] is False


# --------------------------------------------------------------------------- #
# run.grade — end-to-end on samples (functional stubbed for determinism)        #
# --------------------------------------------------------------------------- #

def _stub_functional(monkeypatch, score, gate_passed):
    """Replace the functional module's analyze() so grade() needs no Docker."""
    from modules import functional
    monkeypatch.setattr(
        functional, "analyze",
        lambda code_dir: {"score": score, "gate_passed": gate_passed, "findings": []})


def _read_prompt(samples_dir, app):
    with open(f"{samples_dir}/{app}/prompt.md", encoding="utf-8") as fh:
        return fh.read()


def test_grade_insecure_fails(samples_dir, monkeypatch):
    _stub_functional(monkeypatch, score=67, gate_passed=True)
    prompt = _read_prompt(samples_dir, "insecure_app")
    res = run.grade(f"{samples_dir}/insecure_app", prompt)
    # Insecure app: static modules score badly => overall FAIL.
    assert res["modules"]["secure_coding"]["score"] == 0.0
    assert res["passed"] is False


def test_grade_gate_failure_caps_final(samples_dir, monkeypatch):
    # Even a clean static app is capped when the functional gate fails.
    _stub_functional(monkeypatch, score=0, gate_passed=False)
    prompt = _read_prompt(samples_dir, "secure_app")
    res = run.grade(f"{samples_dir}/secure_app", prompt)
    assert res["gate_passed"] is False
    assert res["final_score"] <= config.FUNCTIONAL_GATE_CAP
    assert res["passed"] is False


def test_grade_secure_app_passes(samples_dir, monkeypatch):
    """Secure app with a passing functional gate scores well and PASSES."""
    _stub_functional(monkeypatch, score=100, gate_passed=True)
    prompt = _read_prompt(samples_dir, "secure_app")
    res = run.grade(f"{samples_dir}/secure_app", prompt)
    assert res["modules"]["secure_coding"]["score"] == 100.0
    assert res["modules"]["dependencies"]["score"] == 100.0
    assert res["modules"]["prompt_quality"]["score"] > 70
    assert res["gate_passed"] is True
    assert res["passed"] is True
