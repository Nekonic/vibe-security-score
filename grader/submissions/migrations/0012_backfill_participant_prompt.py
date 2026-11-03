"""Backfill ``participant_prompt`` for rows submitted before 0010 added it.

Those rows kept only the full Codex prompt, built by ``views._build_prompt`` as
``<system prompt>.rstrip() + "\\n\\n" + <participant prompt>.strip() + "\\n"``. Their
re-grade then used ``len("") == 0`` as the prompt length, so the efficiency
multiplier came out 1.0.

The system prompt has changed since (uncommitted server edits included), so the
current ``config/default_prompt.md`` is not a reliable prefix. Every version ends
with the same closing paragraph, ``_ANCHOR``, which occurs once in it: the
participant prompt is what follows its first occurrence. A row is changed only
when the inversion is exact (the rebuilt prompt equals the stored one); otherwise
it is left as is.

For DONE rows that already had the multiplier applied (``efficiency`` set), the
score is recomputed exactly as ``efficiency.apply`` does at the end of scoring:
``final = round(security_score * multiplier(chars), 2)``. ``security_score`` is the
stored pre-multiplier score, so no re-grade (and no re-run of the checks) is needed.
"""
from django.db import migrations

_ANCHOR = "최종 답변에는 생성 파일, 실행 명령, 테스트한 API와 상태 코드만 **간단히** 적는다."


def recover_participant_prompt(prompt: str):
    """The participant's part of a built prompt, or None when not exactly recoverable."""
    head, sep, tail = prompt.partition(_ANCHOR + "\n\n")
    if not sep or not tail.endswith("\n"):
        return None
    participant = tail[:-1]
    if not participant or participant != participant.strip():
        return None
    system = head + _ANCHOR
    if f"{system.rstrip()}\n\n{participant.strip()}\n" != prompt:
        return None
    return participant


def _multiplier():
    try:
        from scoring.config import load_config
        from scoring.engine import efficiency
        cfg = load_config()
    except Exception:
        return None
    if not cfg.get("efficiency.enabled", False):
        return None
    return lambda chars: efficiency.multiplier(chars, cfg)


def backfill(apps, schema_editor):
    Submission = apps.get_model("submissions", "Submission")
    multiplier = _multiplier()
    for sub in Submission.objects.filter(participant_prompt=""):
        participant = recover_participant_prompt(sub.prompt or "")
        if participant is None:
            continue
        sub.participant_prompt = participant
        fields = ["participant_prompt"]
        rescore = (multiplier is not None and sub.status == "done"
                   and sub.efficiency is not None and sub.security_score is not None)
        if rescore:
            m = multiplier(len(participant))
            sub.prompt_chars = len(participant)
            sub.efficiency = m
            sub.final_score = round(float(sub.security_score) * m, 2)
            fields += ["prompt_chars", "efficiency", "final_score"]
        sub.save(update_fields=fields)


class Migration(migrations.Migration):

    dependencies = [
        ("submissions", "0011_remove_submission_grade_pass_fail"),
    ]

    operations = [
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
