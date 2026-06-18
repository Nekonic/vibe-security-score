"""Prompt quality analyzer using coverage + density metrics.

Scores how security-aware a participant's prompt text is, using a density
metric (NOT mere keyword presence). Rewards concise, concept-dense prompts
and penalizes padding.

Score = 100 * (COVERAGE_WEIGHT * coverage + DENSITY_WEIGHT * density)

where:
  - coverage = (# concepts hit) / (# concepts)
  - density = clamp((distinct concept hits) / (words / DENSITY_WORDS_PER_HIT), 0, 1)
  - words = token count; if < PROMPT_MIN_WORDS, density = 0

Findings include one per concept (passed = covered) plus one summary
for density (passed = density >= 0.5).
"""

import re
from config import (
    PROMPT_COVERAGE_WEIGHT,
    PROMPT_DENSITY_WEIGHT,
    PROMPT_SECURITY_CONCEPTS,
    DENSITY_WORDS_PER_HIT,
    PROMPT_MIN_WORDS,
)


def analyze(prompt_text: str) -> dict:
    """Analyze prompt text for security awareness.

    Args:
        prompt_text: The participant's prompt text to analyze.

    Returns:
        {
            "score": float (0..100),
            "findings": [
                {
                    "id": str,
                    "label": str,
                    "passed": bool,
                    "penalty": float (always 0 for this additive module),
                    "reason": str (Korean),
                    "evidence": str or None,
                },
                ...
            ],
        }
    """
    # Handle empty or whitespace-only prompts
    if not prompt_text or not prompt_text.strip():
        return {
            "score": 0.0,
            "findings": [],
        }

    prompt_lower = prompt_text.lower()

    # Count words (simple whitespace-based tokenization)
    words = prompt_text.split()
    word_count = len(words)

    # Track which concepts are covered and collect evidence
    covered_concepts = set()
    concept_evidence = {}  # concept -> matched alias

    for concept, aliases in PROMPT_SECURITY_CONCEPTS.items():
        for alias in aliases:
            if _matches_alias(alias, prompt_lower):
                covered_concepts.add(concept)
                concept_evidence[concept] = alias
                break  # Found a match for this concept, move to next

    # Calculate metrics
    total_concepts = len(PROMPT_SECURITY_CONCEPTS)
    coverage = len(covered_concepts) / total_concepts if total_concepts > 0 else 0.0

    # Density calculation
    if word_count < PROMPT_MIN_WORDS:
        density = 0.0
    else:
        # covered_concepts * DENSITY_WORDS_PER_HIT / words, clamped to [0, 1]
        raw_density = (len(covered_concepts) * DENSITY_WORDS_PER_HIT) / word_count
        density = min(max(raw_density, 0.0), 1.0)

    # Final score
    score = 100.0 * (PROMPT_COVERAGE_WEIGHT * coverage + PROMPT_DENSITY_WEIGHT * density)

    # Generate findings: one per concept + one for density summary
    findings = []

    # Per-concept findings
    for concept in sorted(PROMPT_SECURITY_CONCEPTS.keys()):
        is_covered = concept in covered_concepts
        evidence = concept_evidence.get(concept)

        finding = {
            "id": concept,
            "label": _concept_label(concept),
            "passed": is_covered,
            "penalty": 0,  # Additive module: no penalties, findings are informational
            "reason": _concept_reason(concept, is_covered),
            "evidence": evidence,
        }
        findings.append(finding)

    # Density summary finding
    density_passed = density >= 0.5
    density_finding = {
        "id": "density_summary",
        "label": "개념 밀도 (Concept Density)",
        "passed": density_passed,
        "penalty": 0,
        "reason": (
            f"프롬프트의 개념 밀도는 {density:.2f}입니다. "
            f"단어 수: {word_count}. "
            f"간결성과 개념 밀도가 높을수록 점수가 높습니다."
        ),
        "evidence": None,
    }
    findings.append(density_finding)

    return {
        "score": score,
        "findings": findings,
    }


def _matches_alias(alias: str, prompt_lower: str) -> bool:
    """Check if an alias matches in the prompt.

    For single-word aliases: use word-boundary matching (case-insensitive).
    For multi-word aliases: match as phrases (whitespace-flexible).

    Args:
        alias: The alias term to search for.
        prompt_lower: The lowercased prompt text.

    Returns:
        True if the alias is found with appropriate matching.
    """
    words = alias.split()

    if len(words) == 1:
        # Single word: use word boundaries
        pattern = r'\b' + re.escape(words[0]) + r'\b'
        return bool(re.search(pattern, prompt_lower))
    else:
        # Multi-word: match as a phrase (whitespace-flexible)
        # Build a pattern that allows flexible whitespace between words
        escaped_words = [re.escape(w) for w in words]
        pattern = r'\s+'.join(escaped_words)
        return bool(re.search(pattern, prompt_lower))


def _concept_label(concept: str) -> str:
    """Generate a human-readable label for a concept."""
    # Convert snake_case to Title Case with spaces
    return concept.replace('_', ' ').title()


def _concept_reason(concept: str, is_covered: bool) -> str:
    """Generate a Korean reason message for a concept finding."""
    concept_korean = {
        "password_hashing": "비밀번호 해싱",
        "csrf": "CSRF 공격 방지",
        "sql_injection": "SQL 인젝션 방지",
        "session_cookies": "세션 쿠키 보안",
        "input_validation": "입력 검증",
        "xss": "XSS 공격 방지",
        "secret_management": "비밀 관리",
        "security_headers": "보안 헤더",
        "rate_limiting": "레이트 리미팅",
        "auth_general": "인증 및 권한 관리",
    }

    label = concept_korean.get(concept, concept)

    if is_covered:
        return f"프롬프트에 '{label}' 관련 보안 개념이 언급되어 있습니다."
    else:
        return f"프롬프트에 '{label}' 관련 보안 개념 언급이 없습니다."
