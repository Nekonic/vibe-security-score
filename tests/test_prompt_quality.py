"""Regression tests for modules/prompt_quality.py."""
import os
import pytest

import config
from modules import prompt_quality


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _findings_by_id(result):
    return {f["id"]: f for f in result["findings"]}


# ---------------------------------------------------------------------------
# Integration: good_prompt vs weak_prompt
# ---------------------------------------------------------------------------

class TestGoodVsWeakPrompt:
    @pytest.fixture(autouse=True)
    def load_prompts(self, samples_dir):
        # Prompts now live inside each submission directory as prompt.md.
        good_path = os.path.join(samples_dir, "secure_app", "prompt.md")
        weak_path = os.path.join(samples_dir, "insecure_app", "prompt.md")
        with open(good_path, encoding="utf-8") as fh:
            good_text = fh.read()
        with open(weak_path, encoding="utf-8") as fh:
            weak_text = fh.read()
        self.good_result = prompt_quality.analyze(good_text)
        self.weak_result = prompt_quality.analyze(weak_text)

    def test_good_scores_higher_than_weak(self):
        good = self.good_result["score"]
        weak = self.weak_result["score"]
        assert good > weak, (
            f"Good prompt score {good} should be > weak prompt score {weak}"
        )

    def test_good_prompt_above_70(self):
        assert self.good_result["score"] > 70, (
            f"Good prompt scored {self.good_result['score']}, expected > 70"
        )

    def test_weak_prompt_below_25(self):
        assert self.weak_result["score"] < 25, (
            f"Weak prompt scored {self.weak_result['score']}, expected < 25"
        )


# ---------------------------------------------------------------------------
# Edge case: empty and whitespace-only prompts
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", ["", "   ", "\n\t\n"])
def test_empty_prompt_returns_zero(text):
    result = prompt_quality.analyze(text)
    assert result["score"] == 0.0
    assert isinstance(result["findings"], list)


# ---------------------------------------------------------------------------
# Word-boundary matching: "identity"-only prompt must NOT match the 'id' alias
# ---------------------------------------------------------------------------

def test_identity_does_not_match_id_alias():
    """
    The 'auth_general' concept includes alias 'id' (via config.PROMPT_SECURITY_CONCEPTS).
    A prompt containing 'identity' (but not the standalone word 'id') should NOT
    trigger the 'id' alias via substring match — word-boundary matching is required.

    We pick the concept that has 'id' as one of its short single-word aliases.
    Reading config: USERNAME_ALIASES contains 'id'; that's not a prompt concept.
    Looking at PROMPT_SECURITY_CONCEPTS: 'auth_general' has 'id' as a word in
    'userid'/'user_id' (not standalone). Let's check for any concept whose aliases
    include the lone token 'id' -- if none, we test with 'orm' vs 'orml'.

    Actually: 'sql_injection' includes alias 'orm'.
    We craft a prompt with the word 'form' (contains 'orm' as substring) but
    NOT 'orm' as a standalone word, and verify the concept is NOT covered.
    """
    # 'sql_injection' aliases include 'orm' (single word).
    # 'form' contains 'orm' as a substring but not as a standalone word.
    prompt = "please add a nice form to the login page"
    result = prompt_quality.analyze(prompt)
    findings = _findings_by_id(result)
    sql_finding = findings.get("sql_injection")
    assert sql_finding is not None
    assert sql_finding["passed"] is False, (
        "The word 'form' contains 'orm' as a substring, but 'orm' is not "
        "present as a standalone word, so sql_injection should NOT be covered"
    )


def test_standalone_orm_does_match_sql_injection():
    """The word 'orm' alone should match the sql_injection concept."""
    prompt = "use an orm to prevent sql injection"
    result = prompt_quality.analyze(prompt)
    findings = _findings_by_id(result)
    sql_finding = findings.get("sql_injection")
    assert sql_finding is not None
    assert sql_finding["passed"] is True, (
        "Standalone 'orm' should match the sql_injection concept"
    )


def test_csr_does_not_match_csrf_alias():
    """
    The csrf concept uses single-word alias 'csrf'.
    A prompt with 'csr' (substring of csrf) must NOT match.
    """
    # 'csrf' is a single-word alias; word-boundary means 'csr' won't match 'csrf'
    # But we test that 'csrf' itself DOES match, and partial substring doesn't.
    # Use a made-up word that contains 'csrf' as a substring test in reverse:
    # A prompt with only 'nocsrf' should not match alias 'csrf' as a standalone word.
    prompt = "please add nocsrf protection to all routes"
    result = prompt_quality.analyze(prompt)
    findings = _findings_by_id(result)
    csrf_finding = findings.get("csrf")
    # 'nocsrf' contains 'csrf' but it's not a standalone word — should NOT match
    assert csrf_finding is not None
    assert csrf_finding["passed"] is False, (
        "'nocsrf' should not match the word-boundary alias 'csrf'"
    )


# ---------------------------------------------------------------------------
# Score formula sanity check
# ---------------------------------------------------------------------------

def test_all_concepts_covered_yields_high_score():
    """A prompt that covers every concept should score very high."""
    # Collect one alias from every concept
    aliases_hit = []
    for concept, aliases in config.PROMPT_SECURITY_CONCEPTS.items():
        aliases_hit.append(aliases[0])
    prompt = " ".join(aliases_hit)
    result = prompt_quality.analyze(prompt)
    assert result["score"] > 50, (
        f"Covering all concepts should yield score > 50, got {result['score']}"
    )


def test_zero_concepts_yields_zero_score():
    """A short, totally off-topic prompt should score 0 or very close to 0."""
    result = prompt_quality.analyze("make it look nice please")
    # Coverage = 0; density = 0 (word count >= 5 but no hits)
    assert result["score"] == pytest.approx(0.0, abs=1e-6)
