"""A05 Injection, spreadsheet export: `GET /admin/users.csv` (spec). A username that
starts with = + - @ must not reach the CSV as a live formula (CWE-1236; ASVS 1.2.10)
— the admin who opens the export in a spreadsheet would run it.
"""
from __future__ import annotations

import re
import uuid

from ..shared.http import _body_text, _ok, _snip, new_account
from .base import Check, _undecidable, result


def dynamic_csv_injection(check, ctx, cfg):
    admin = ctx.userA  # the first signed-up user is the admin (spec)
    if admin is None or not _ok(ctx.get(admin.session, "/admin/users.csv")):
        return _undecidable(check, cfg, "관리자 CSV 다운로드(GET /admin/users.csv)를 확인할 수 없음")
    n = str(uuid.uuid4().int)[-4:]
    formula = f"=1+{n}"
    r = new_account(ctx, username=formula, name="", pw_tag="Csv").signup_response
    if r is None or r.status_code >= 500:
        # A crash is not a rejection: only a 4xx refusal counts as a defense.
        return _undecidable(check, cfg, f"수식 아이디 가입이 서버 오류({r.status_code if r is not None else '응답 없음'})라 판정 불가")
    if not _ok(r):
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                      evidence=[_snip(f"수식으로 시작하는 아이디 {formula!r} 가입 거부({r.status_code if r is not None else '응답 없음'})")])
    g = ctx.get(admin.session, "/admin/users.csv")
    text = _body_text(g)
    if not _ok(g) or f"1+{n}" not in text:
        return _undecidable(check, cfg, f"가입한 아이디 {formula!r}가 CSV에 나타나지 않아 판정 불가")
    if re.search(r'(^|[\r\n,"])' + re.escape(formula), text):
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=[f"아이디 {formula!r}가 CSV 셀 맨 앞에 그대로 들어감 → 관리자가 스프레드시트로 열면 수식 실행(CSV Injection)"],
                      evidence=[_snip(next((ln for ln in text.splitlines() if formula in ln), ""))])
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip(f"수식 아이디가 CSV에서 무력화됨: {next((ln for ln in text.splitlines() if f'1+{n}' in ln), '')!r}")])


CHECKS = [
    Check("csv_injection", "CSV Injection", "dynamic", dynamic_csv_injection),
]
