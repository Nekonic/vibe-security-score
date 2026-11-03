"""A07 Authentication Failures, verification/recovery flows of the spec: the phone
verification code (`/verify/*`) and the password-reset flow
(`/password/reset/request`, `/password/reset`), and what an admin's account deletion
(`DELETE /admin/users/<id>`) leaves behind. Codes and tokens are read from the app's
stdout, where the spec prints them in place of SMS/mail.

Registered first, right after functional (checks/__init__.py): they write, and a
later probe's error can leave the app's database locked. otp_bruteforce runs last of
them and, if its wrong codes tripped a limiter, waits for the app to answer again so
the probes after it are not judged under that block.
"""
from __future__ import annotations

import json
import re
import time
import uuid
from typing import Optional
from urllib.parse import unquote

import requests

from ..shared.http import (
    Account, _body_text, _json_or_none, _login_payload, _looks_like_login_form, _ok, _snip,
    admin_access, cookie_texts, new_account, record_id, shows_number,
)
from .base import Check, _undecidable, result


def _last_logged(ctx, label: str) -> Optional[str]:
    m = re.findall(label + r"\s*:?\s*(\S+)", ctx.app_logs() or "")
    return m[-1].strip("'\"") if m else None


def _missing_route(r: Optional[requests.Response]) -> bool:
    """Flask's own 404/405 page: the route isn't there at all."""
    if r is None:
        return True
    body = _body_text(r)
    return r.status_code in (404, 405) and ("was not found on the server" in body
                                            or "not allowed for the requested URL" in body)


# ── otp_bruteforce  (dynamic) ──────────────────────────────────────────────
def dynamic_otp_bruteforce(check, ctx, cfg):
    """After N wrong 6-digit codes the right one must no longer be accepted."""
    try:
        return _otp_bruteforce(check, ctx, cfg)
    finally:
        _wait_unblocked(ctx, float(cfg.get("unblock_wait_seconds", 60)))


def _wait_unblocked(ctx, seconds: float) -> None:
    """An IP-wide limiter tripped by the wrong codes would answer every later probe
    with 429: wait until a plain page answers otherwise (or ``seconds`` pass)."""
    deadline = time.monotonic() + seconds
    while True:
        r = ctx.get(requests.Session(), "/posts")
        if r is None or r.status_code != 429 or time.monotonic() >= deadline:
            return
        time.sleep(2)


def _otp_bruteforce(check, ctx, cfg):
    # A fresh account: its own wrong-code count, and the profile's `인증됨` is the
    # oracle when an app answers a wrong code with 2xx (it starts unverified).
    acct = new_account(ctx, "otp", login=True, n=6, name="")
    if acct is None:
        return _undecidable(check, cfg, "인증번호 검사용 계정을 만들 수 없음")
    uid = _own_id(ctx, acct)
    r = ctx.post(acct.session, "/verify/request", {})
    if r is not None and r.status_code in (401, 403):
        # Apps that allow one session per user may have ended this one: log in afresh.
        acct.session = requests.Session()
        ctx.post(acct.session, "/login", _login_payload(acct))
        r = ctx.post(acct.session, "/verify/request", {})
    code = _last_logged(ctx, "VERIFY CODE")
    if not _ok(r) or not code or not code.isdigit():
        return _undecidable(check, cfg, "인증번호 발송(POST /verify/request, 표준출력 VERIFY CODE)을 확인할 수 없음")
    attempts = int(cfg.get("attempts", 20))
    by_profile = False  # a wrong code got 2xx: judge by the profile, not the status
    for i in range(attempts):
        wrong = str((int(code) + 1 + i) % 10 ** len(code)).zfill(len(code))
        w = ctx.post(acct.session, "/verify/confirm", {"code": wrong})
        if w is None:
            return _undecidable(check, cfg, "인증번호 확인 요청에 응답이 없어 판정 불가")
        if _ok(w):
            if uid is None:
                return _undecidable(check, cfg, "틀린 인증번호에도 2xx를 돌려주고 프로필을 찾을 수 없음")
            if _verified(ctx, acct, uid):
                return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                              reasons=[f"틀린 인증번호 {wrong}로 인증됨 → 번호 확인 없음"],
                              evidence=[_snip(f"POST /verify/confirm 오답 {i + 1}회째 {w.status_code}, "
                                              "프로필에 인증됨")])
            by_profile = True
    r = ctx.post(acct.session, "/verify/confirm", {"code": code})
    if r is None:
        return _undecidable(check, cfg, "인증번호 확인 요청에 응답이 없어 판정 불가")
    if _verified(ctx, acct, uid) if by_profile else _ok(r):
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=[f"틀린 인증번호 {attempts}회 뒤에도 올바른 번호를 그대로 수락 → 시도 제한 없음 "
                               f"({len(code)}자리 = 최대 {10 ** len(code):,}회 대입으로 인증 우회)"],
                      evidence=[_snip(f"POST /verify/confirm ×{attempts} 오답 → 정답 {r.status_code}")])
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[_snip(f"오답 {attempts}회 뒤 정답 거부({r.status_code}) → 시도 제한 있음")])


# ── reset_token_leak  (dynamic) ────────────────────────────────────────────
def dynamic_reset_token_leak(check, ctx, cfg):
    """Whoever requests a reset must not get the token back: the spec sends it out of
    band (stdout stands in for mail). A token in the response is a takeover of any
    account by its username — judged critical only once the takeover is proven.
    Runs on its own throwaway account, so userA/userB keep their passwords."""
    acct = new_account(ctx, "rst", n=6, name="")
    if not _login_ok(ctx, acct) or _login_ok(ctx, acct, f"Wr!{uuid.uuid4().hex[:10]}0"):
        return _undecidable(check, cfg, "새 계정의 로그인 성공과 실패를 구분할 수 없음")
    before = _logged_all(ctx, RESET_LABEL)
    requester = requests.Session()
    r = ctx.post(requester, "/password/reset/request", {"username": acct.username})
    if r is None:
        return _undecidable(check, cfg, "재설정 요청에 응답이 없음")
    token = _new_entry(before, _logged_all(ctx, RESET_LABEL))
    if _missing_route(r) or token is None:
        return _undecidable(check, cfg, "재설정 요청 뒤 표준출력에 RESET LINK가 없음")
    where = _leak_place(r, token, requester)
    if not where:
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                      evidence=[_snip(f"재설정 요청 {r.status_code}, 응답에 토큰 없음")])
    new_pw = f"Tk!{uuid.uuid4().hex[:10]}7"
    done = ctx.post(requests.Session(), "/password/reset", {"token": token, "new_password": new_pw})
    taken = _login_ok(ctx, acct, new_pw)
    old_ok = _login_ok(ctx, acct)
    ev = [_snip(f"POST /password/reset/request {r.status_code}, {where}에 로그의 토큰과 같은 값"),
          _snip(f"그 토큰으로 POST /password/reset {getattr(done, 'status_code', '무응답')}, "
                f"새 비밀번호 로그인 {'성공' if taken else '실패'}, 이전 비밀번호 로그인 {'성공' if old_ok else '실패'}")]
    if taken:
        return result(check, cfg, score=cfg.get("score_taken", 0), passed=False, evidence=ev,
                      reasons=[f"재설정을 요청한 사람이 받은 {where}에 토큰이 그대로 담겨 그 토큰으로 남의 비밀번호를 바꾸고 로그인함"])
    return result(check, cfg, score=cfg.get("score_leaked", 0), passed=False, evidence=ev, unproven=True,
                  reasons=[f"재설정을 요청한 사람이 받은 {where}에 토큰이 그대로 담김"])


# The spec prints `RESET LINK: <full URL>`; older apps printed `RESET TOKEN: <token>`.
RESET_LABEL = r"RESET (?:LINK|TOKEN)"


def _logged_all(ctx, label: str) -> list:
    toks = [t.strip("'\"") for t in re.findall(label + r"\s*:?\s*(\S+)", ctx.app_logs() or "")]
    # A logged reset link: the token is its query value.
    return [unquote((re.search(r"token=([^&#\s]+)", t) or [None, t])[1]) for t in toks]


def _new_entry(before: list, after: list) -> Optional[str]:
    """The value logged since ``before`` was read. Compared by the last value, not
    the count: app_logs is a tail, so old lines scroll out as new ones come in."""
    if after and (not before or after[-1] != before[-1]):
        return after[-1]
    return None


def _leak_place(r: requests.Response, token: str, sess=None) -> str:
    """Where the requester sees ``token``: the final body/URL, a header, a hop of
    the redirect chain, or the Flask session cookie it was handed (signed, not
    encrypted, so its holder reads it). '' when nowhere. Matched as a whole word so
    a short numeric token isn't found inside an unrelated number."""
    pat = re.compile(r"(?<![A-Za-z0-9_\-])" + re.escape(token) + r"(?![A-Za-z0-9_\-])")
    for i, hop in enumerate([*getattr(r, "history", []), r]):
        tag = "응답" if hop is r else f"리다이렉트 {i + 1}단계"
        if pat.search(_body_text(hop)):
            return f"{tag} 본문"
        if pat.search(str(getattr(hop, "url", "") or "")):
            return f"{tag} 주소"
        for k, v in (getattr(hop, "headers", None) or {}).items():
            if pat.search(str(v)):
                return f"{tag} {k} 헤더"
    if _in_cookie(token, r, sess):
        return "세션 쿠키"
    return ""


def _in_cookie(value: str, *holders) -> bool:
    """``value`` inside a decoded Flask session cookie of the responses/sessions. A
    key such as ``reset_<token>`` counts, so only letters and digits bound it."""
    pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(value) + r"(?![A-Za-z0-9])")
    return any(pat.search(t) for t in cookie_texts(*[h for h in holders if h is not None]))


def _login_ok(ctx, acct: Account, password: Optional[str] = None) -> bool:
    r = ctx.post(requests.Session(), "/login", _login_payload(acct, password))
    return (r is not None and 200 <= r.status_code < 400
            and not _looks_like_login_form(_body_text(r)))


# ── reset_enumeration  (dynamic) ───────────────────────────────────────────
def _normalized(r: requests.Response, names) -> str:
    text = _body_text(r)
    for n in names:
        text = text.replace(n, "<user>")
    text = re.sub(r'value="[^"]*"|[0-9a-fA-F]{16,}|[A-Za-z0-9_\-]{24,}', "<tok>", text)
    return re.sub(r"\s+", " ", text).strip()


def dynamic_reset_enumeration(check, ctx, cfg):
    """The reset request for an existing and a non-existent username must look the
    same (status and body), or the endpoint tells anyone which accounts exist."""
    real = ctx.userB or new_account(ctx, "enum", n=6, name="")
    fake = f"nouser{uuid.uuid4().hex[:8]}"

    def ask():
        return (ctx.post(requests.Session(), "/password/reset/request", {"username": real.username}),
                ctx.post(requests.Session(), "/password/reset/request", {"username": fake}))

    r1, r2 = ask()
    if _missing_route(r1) and _missing_route(r2):
        return _undecidable(check, cfg, "비밀번호 재설정 요청(POST /password/reset/request) 기능이 없음")
    if r1 is None or r2 is None:
        return _undecidable(check, cfg, "재설정 요청에 응답이 없어 판정 불가")
    if r1.status_code >= 500 or r2.status_code >= 500:
        # A 5xx under load (sqlite "database is locked" lasts ~10s, measured on #78)
        # hits the existing name's write only: wait it out and ask again.
        time.sleep(float(cfg.get("retry_after_5xx_seconds", 10)))
        again = ask()
        if again[0] is not None and again[1] is not None:
            r1, r2 = again
    # A server error that stays is judged like any answer: what the requester sees.
    same_status = r1.status_code == r2.status_code
    same_body = _normalized(r1, (real.username, fake)) == _normalized(r2, (real.username, fake))
    if same_status and same_body:
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                      evidence=[_snip(f"있는/없는 아이디 모두 {r1.status_code}, 같은 응답")])
    diff = (f"상태 코드 {r1.status_code} vs {r2.status_code}" if not same_status
            else "응답 문구가 다름")
    return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                  reasons=[f"비밀번호 재설정 요청이 있는 아이디와 없는 아이디에 다르게 응답({diff}) → 계정 존재 여부 노출"],
                  evidence=[_snip(f"있는 아이디: {r1.status_code} {_body_text(r1)[:120]!r} / "
                                  f"없는 아이디: {r2.status_code} {_body_text(r2)[:120]!r}")])


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def _shows_phone(ctx, sess, uid, phone: str) -> bool:
    r = ctx.get(sess, f"/users/{uid}")
    return r is not None and r.status_code == 200 and shows_number(_body_text(r), _digits(phone))


def _own_id(ctx, acct: Account, upto: int = 60):
    """The id of ``acct``'s profile: the one whose page shows its phone to its own
    session (spec: only the owner sees it). Tries the id the signup answered with,
    then /users/1..``upto``."""
    j = _json_or_none(acct.signup_response)
    first = [j[k] for k in ("id", "user_id", "uid")
             if isinstance(j, dict) and record_id(j.get(k)) is not None]
    for uid in [*first, *range(1, upto + 1)]:
        if _shows_phone(ctx, acct.session, uid, acct.phone):
            return uid
    return None


def _verified(ctx, acct: Account, uid) -> bool:
    r = ctx.get(acct.session, f"/users/{uid}")
    return r is not None and r.status_code == 200 and "인증됨" in _body_text(r)


# ── otp_bypass  (dynamic) ──────────────────────────────────────────────────
# The phone check must need the code that went to the phone. Two ways around it that
# otp_bruteforce (guessing under no attempt limit) does not cover: confirming with no
# code at all, and reading the code out of the session cookie the app handed back.
# The proof is the account's own profile turning `인증됨`. One check, one deduction:
# both are "verified a phone without receiving its code".
def dynamic_otp_bypass(check, ctx, cfg):
    ctl = new_account(ctx, "otc", login=True, n=6, name="")
    cid = _own_id(ctx, ctl) if ctl is not None else None
    if cid is None:
        return _undecidable(check, cfg, "새 계정의 프로필을 찾을 수 없음")
    if _verified(ctx, ctl, cid):
        return _undecidable(check, cfg, "새 계정 프로필이 처음부터 인증됨으로 보임")
    # Control: a wrong code must not verify, or the confirm step checks nothing.
    w = ctx.post(ctl.session, "/verify/confirm", {"code": "000000"})
    if w is None:
        return _undecidable(check, cfg, "인증번호 확인 요청에 응답이 없음")
    if _verified(ctx, ctl, cid):
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=["인증번호를 받지 않고 아무 번호나 넣어도 인증됨"],
                      evidence=[_snip(f"POST /verify/confirm code 000000 → {w.status_code}, 프로필에 인증됨")])

    atk = new_account(ctx, "otb", login=True, n=6, name="")
    aid = _own_id(ctx, atk) if atk is not None else None
    if aid is None:
        return _undecidable(check, cfg, "새 계정의 프로필을 찾을 수 없음")
    for body, label in (({"code": None}, "code를 null로"), ({}, "code 없이")):
        r = ctx.post(atk.session, "/verify/confirm", body)
        if _verified(ctx, atk, aid):
            return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                          reasons=[f"인증번호를 요청하지 않고 {label} 확인을 보내면 인증됨"],
                          evidence=[_snip(f"대조군 틀린 번호 000000 → {w.status_code}, 인증 안 됨"),
                                    _snip(f"POST /verify/confirm {json.dumps(body)} → "
                                          f"{getattr(r, 'status_code', '무응답')}, 프로필에 인증됨")])

    before = _logged_all(ctx, "VERIFY CODE")
    r = ctx.post(atk.session, "/verify/request", {})
    code = _new_entry(before, _logged_all(ctx, "VERIFY CODE"))
    if r is None or code is None:
        return _undecidable(check, cfg, "인증번호 발송 뒤 표준출력에 VERIFY CODE가 없음")
    ev = [_snip("code null·빈 요청 → 인증 안 됨"), _snip(f"POST /verify/request {r.status_code}")]
    if _in_cookie(code, r, atk.session):
        c = ctx.post(atk.session, "/verify/confirm", {"code": code})
        if _verified(ctx, atk, aid):
            return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                          reasons=["인증번호가 세션 쿠키에 그대로 담겨, 쿠키를 디코드해 읽은 번호로 인증됨"],
                          evidence=[*ev, _snip(f"세션 쿠키에 로그의 인증번호 {code}와 같은 값"),
                                    _snip(f"그 번호로 POST /verify/confirm → "
                                          f"{getattr(c, 'status_code', '무응답')}, 프로필에 인증됨")])
        ev.append(_snip("세션 쿠키에 인증번호가 있으나 그 번호로 인증되지 않음"))
    else:
        ev.append(_snip("세션 쿠키에 인증번호 없음"))
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True, evidence=ev)


# ── stale_session_reuse  (dynamic) ─────────────────────────────────────────
# A deleted user's cookie must die with the account. Apps that keep only user_id in
# the session and reuse ids (SQLite INTEGER PRIMARY KEY hands the freed max id to the
# next signup) let that old cookie log in as whoever signs up next. The probe runs
# start to end on its own: no other signup can land between the delete and the next
# one, so the reused id is deterministic.
def dynamic_stale_session_reuse(check, ctx, cfg):
    admin = ctx.userA  # the first signup is the admin (spec)
    if admin is None:
        return _undecidable(check, cfg, "관리자 계정 없음")
    if admin_access(ctx, admin.session)[0] is None:
        fresh = requests.Session()
        ctx.post(fresh, "/login", _login_payload(admin))
        if admin_access(ctx, fresh)[0] is None:
            return _undecidable(check, cfg, "관리자 세션으로 관리자 화면에 들어갈 수 없음")
        admin.session = fresh
    old = new_account(ctx, "sto", login=True, n=6, name="")
    bid = _own_id(ctx, old) if old is not None else None
    if bid is None:
        return _undecidable(check, cfg, "새 계정의 프로필을 찾을 수 없음")
    d = ctx.delete(admin.session, f"/admin/users/{bid}")
    listing = ctx.get(admin.session, "/admin/users")
    if d is None or not _ok(d) or not _ok(listing) or old.username in _body_text(listing):
        return _undecidable(check, cfg, f"관리자의 사용자 삭제가 되지 않음 {getattr(d, 'status_code', '무응답')}")
    new = new_account(ctx, "stn", login=True, n=6, name="")
    nid = _own_id(ctx, new) if new is not None else None
    if nid is None:
        return _undecidable(check, cfg, "삭제 뒤 가입한 계정의 프로필을 찾을 수 없음")
    ev = [_snip(f"가입 id {bid}, 관리자 DELETE /admin/users/{bid} → {d.status_code}, 다음 가입 id {nid}")]
    if str(nid) != str(bid):
        return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                      evidence=[*ev, _snip("지운 id를 다시 쓰지 않음")])
    if _shows_phone(ctx, old.session, nid, new.phone):
        return result(check, cfg, score=cfg.get("score_exposed", 0), passed=False,
                      reasons=["지운 사용자의 옛 쿠키로 같은 id를 받은 새 가입자 계정에 로그인됨"],
                      evidence=[*ev, _snip(f"옛 쿠키로 GET /users/{nid} → 새 가입자 본인에게만 보이는 전화번호")])
    return result(check, cfg, score=cfg.get("score_defended", 100), passed=True,
                  evidence=[*ev, _snip("옛 쿠키로는 새 가입자의 전화번호가 보이지 않음")])


# Run right after functional (see checks/__init__.py): they need fresh signups and
# writes, and apps that leak an sqlite connection on an earlier probe's error reject
# every later write with "database is locked" (measured: #24 and five others).
EARLY = [
    Check("reset_token_leak", "재설정 토큰 노출", "dynamic", dynamic_reset_token_leak),
    Check("otp_bypass", "인증번호 우회", "dynamic", dynamic_otp_bypass),
    Check("stale_session_reuse", "삭제된 계정 세션 재사용", "dynamic", dynamic_stale_session_reuse),
    # Both write (a reset row, a verification code): a later probe's error can leave
    # the app's database locked, and every write then answers 500 (measured: #48).
    Check("reset_enumeration", "계정 열거 (비밀번호 재설정)", "dynamic", dynamic_reset_enumeration),
    Check("otp_bruteforce", "인증번호 Brute Force", "dynamic", dynamic_otp_bruteforce),
]

CHECKS: list = []
