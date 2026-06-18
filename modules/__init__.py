"""Analysis modules for the vibe-security-score grader.

Each module exposes a single entry point:

    analyze(...) -> dict

returning the shared result contract:

    {
        "score": float,            # 0..100 sub-score for this module
        "findings": [Finding, ...],
        # functional module additionally returns:
        "gate_passed": bool,
    }

Finding (plain dict):
    {
        "id": str,            # stable id, e.g. "hardcoded_secret"
        "label": str,         # human title, e.g. "Hardcoded secret key"
        "passed": bool,       # True => ✔ (no issue), False => ✘ (issue found)
        "penalty": float,     # points deducted (0 if passed/neutral)
        "reason": str,        # educational explanation (the teaching payload)
        "evidence": str|None, # optional snippet / file:line / package name
        "skipped": bool,      # optional; True if the check could not run
    }

Signatures:
    secure_coding.analyze(code_dir: str) -> dict
    dependencies.analyze(code_dir: str) -> dict
    prompt_quality.analyze(prompt_text: str) -> dict
    functional.analyze(code_dir: str) -> dict   # includes "gate_passed"
"""
