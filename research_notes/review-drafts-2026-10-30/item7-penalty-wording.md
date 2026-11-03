# 감점 사유 문구 시안

코드는 고치지 않았다. 2026-10-30 현재 코드 기준 위치다.

| 항목 | 수 |
|---|---|
| 전체 문자열 | 146 |
| 바꿀 문장 | 133 |
| 그대로 | 13 |
| 코드 한 줄도 바꿔야 하는 곳 | 10 |

- 범위: `reasons=`, `penalty_reasons`, `_undecidable(...)` 사유, critical `repro`와 `severity`, 괄호가 든 검사 이름
- 판정 불가 사유는 본문만 적었다. 앞머리 `판정 불가: `는 base.py:71과 http.py:398이 붙인다
- 판정 불가 사유는 관리자 화면과 Kali에만 보인다
- `severity`는 문장이 아니라 배지라서 `·` 구분은 두고 괄호만 뺐다

## scoring/checks/base.py, scoring/shared/http.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| base.py:71 | `f"검사 생략(판정 불가): {reason}"` | `f"판정 불가: {reason}"` |
| http.py:398 | `f"검사 생략(판정 불가): {reason}"` | `f"판정 불가: {reason}"` |

## scoring/checks/A01_broken_access_control.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| A01:70 | 테스트 계정 없음으로 판정 불가 | 테스트 계정 없음 |
| A01:75 | 정상 글 작성이 목록에 보이지 않아 CSRF 판정 불가 | 정상 글 작성 확인 불가 |
| A01:79 | 위조 요청에 응답이 없거나 서버 오류라 판정 불가 | 위조 요청 무응답 또는 서버 오류 |
| A01:82 | 글 목록 확인 불가로 판정 불가 | 글 목록 확인 불가 |
| A01:90 | 토큰·Origin 검증 없이 SameSite 쿠키에만 의존 → 브라우저 정책 의존(ASVS 3.5.1은 토큰 등 명시적 방어 요구) | CSRF 토큰 없이 SameSite에만 의존 |
| A01:93 | 세션 쿠키가 없어 SameSite 판정 불가 | 세션 쿠키 없음 |
| A01:95 | 외부 사이트 폼으로 로그인 사용자의 글 작성이 위조됨 → CSRF(토큰·Origin 검증·SameSite 모두 없음) | 외부 사이트에서 글 작성 위조 성공 |
| A01:102 | 테스트 계정 구성 부족으로 IDOR 판정 불가 | 테스트 계정 부족 |
| A01:106 | userA의 phone(사적 PII)이 없어 IDOR 판정 불가 | userA 전화번호 없음 |
| A01:110 | userA의 id를 확인할 수 없어 IDOR 판정 불가 | userA id 확인 불가 |
| A01:127 | `f"userB 세션으로 userA({ctx.userA.phone}) 전화번호 조회됨 → IDOR/PII 노출"` | userB가 userA 전화번호 조회 가능 |
| A01:138 통과, 관리자만 | `"본인 전화번호가 프로필에 노출되지 않아 대조군은 못 세웠으나 " f"공격자 접근이 차단됨(HTTP {atk_code}) → 접근 통제 정상"` | `f"userB 요청 HTTP {atk_code}로 차단"` |
| A01:144 | 본인 전화번호도 프로필에 나오지 않아 IDOR 판정 불가(대조군 없음) | 프로필에 전화번호 미노출 |
| A01:196 | 일반 사용자 세션 없음으로 판정 불가 | 일반 사용자 세션 없음 |
| A01:212 | `f"일반 사용자(userB) 세션으로 {p} 노출됨 → 접근 통제 실패"` | `f"일반 사용자가 {p} 접근 가능"` |
| A01:216 | 관리자 페이지 요청에 응답이 없어 판정 불가 | 관리자 페이지 무응답 |
| A01:235 | 가입/로그인 실패로 권한상승 판정 불가 | 가입 또는 로그인 실패 |
| A01:241 | 관리자 페이지가 일반 가입자에게도 열려 Mass Assignment로 분리 판정 불가 | 관리자 페이지가 일반 가입자에게 열림 |
| A01:245 | 관리자 페이지 요청에 응답이 없어 판정 불가 | 관리자 페이지 무응답 |
| A01:248 | `f"가입 요청의 {sorted(extra)} 필드를 신뢰 → 관리자 권한 탈취({atk_path})"` | `f"가입 요청 {fields} 값으로 관리자 권한 탈취"` 코드 변경 1 |
| A01:276 | SSRF 콜백 리스너 미가동으로 판정 불가 | SSRF 콜백 리스너 미가동 |
| A01:278 | 테스트 계정 부족으로 SSRF 판정 불가 | 테스트 계정 부족 |
| A01:298 | 서버가 공격자 지정 사설/호스트 주소를 가져옴 → SSRF(사설 대역 미차단) | 서버가 공격자 지정 내부 주소로 요청 |
| A01:317 | 공개 주소로 위장한 URL의 302 리다이렉트를 따라가 사설/호스트 주소를 가져옴 → SSRF(리다이렉트 경유 필터 우회) | 302 리다이렉트로 SSRF 필터 우회 |
| A01:323 | link_url/avatar_url URL 소비 기능이 없어 SSRF 판정 불가 | link_url, avatar_url 입력 기능 없음 |
| A01:329 | 공개 URL 미리보기도 동작하지 않아(대조군 실패) SSRF 판정 불가 | 공개 URL 미리보기 미동작 |
| A01:375 | 일반 사용자 세션 없음으로 판정 불가 | 일반 사용자 세션 없음 |
| A01:380 | 관리자 페이지가 일반 사용자에게 이미 열려 별도 판정 불가 | 관리자 페이지가 일반 사용자에게 열림 |
| A01:384 | userB id 확인 불가로 판정 불가 | userB id 확인 불가 |
| A01:390 | `f"userB가 /admin/users/{uid}/role 로 스스로 관리자 승격 → 관리자 사용자관리 인가 실패"` | `f"일반 사용자가 /admin/users/{uid}/role로 관리자 승격"` |
| A01:393 | 관리자 페이지 요청에 응답이 없어 판정 불가 | 관리자 페이지 무응답 |
| A01:473 | `f"로그인 후 next 이동 기능을 확인할 수 없음(next=/posts → {code})"` | next 이동 기능 없음 |
| A01:486 | 로그인 후 next로 받은 외부 주소로 그대로 이동 → Open Redirect(피싱 링크에 악용) | 로그인 후 외부 주소로 이동 허용 |
| A01:490 | `외부 URL·//는 막았지만 /\\로 시작하는 주소는 통과 → 브라우저가 //로 해석해 외부로 이동` | `"/\\ 경로로 Open Redirect 필터 우회"` 화면에는 `/\ 경로로` |
| A01:494 | 공격 로그인이 모두 거부되어 판정 불가 | 공격 로그인 모두 거부됨 |

## scoring/checks/A02_security_misconfiguration.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| A02:31 | `f"{path}:{lineno} debug=True 사용"` | 그대로 |
| A02:69 | `f"{m} 보안 헤더 미설정"` | 그대로 |
| A02:87 | 응답 없음으로 판정 불가 | /posts 무응답 |
| A02:102 | `"응답 보안 헤더 누락: " + ", ".join(missing_h)` | `"보안 헤더 미설정: " + ", ".join(missing_h)` |
| A02:106 | `"세션 쿠키 플래그 누락: " + ", ".join(missing_c)` | `"세션 쿠키 플래그 미설정: " + ", ".join(missing_c)` |

## scoring/checks/A03_supply_chain.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| A03:144 | `f"{name}=={version} {cve_id} ({sev}) — {fixed_txt} 에서 수정됨"` | `f"{name}=={version} {cve_id} {sev}, {fix_note}"` 코드 변경 2 |
| A03:212 | `f"{name} — 인기 패키지 '{best_name}'와 편집거리 {best_dist} (Typosquatting 의심)"` | `f"{name} Typosquatting 의심, {best_name}와 {best_dist}자 차이"` |
| A03:370 | `f"{pinned} {cve_id} ({sev})"` | `f"{pinned} {cve_id} {sev}"` |

## scoring/shared/external_tools.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| external_tools:18 | 검사 생략(도구 미설치) | 검사 생략: 도구 미설치 |
| external_tools:19 | 검사 생략(도구 비활성화) | 검사 생략: 도구 비활성화 |
| external_tools:20 | 검사 생략(--dev: 내장 검사 사용, 외부 도구 미실행) | 검사 생략: --dev 내장 검사 사용 |

## scoring/checks/A04_cryptographic_failures.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| A04:58 | `f"{path}:{lineno} SECRET_KEY 하드코딩"` | 그대로 |
| A04:115 | `f"{path}:{lineno} 환경변수 미설정 시 하드코딩된 기본 SECRET_KEY로 fallback"` | `f"{path}:{lineno} SECRET_KEY 기본값 하드코딩"` |
| A04:165 | `f"{...}:{...} 평문 비밀번호 비교"` | 그대로 |
| A04:170 | `f"{...}:{...} 빠른 해시(md5·sha 계열) 사용 → 솔트·반복 없는 비밀번호 저장"` | `f"{...}:{...} 비밀번호에 빠른 해시 사용"` |
| A04:176 | 명확한 비밀번호 해싱 로직을 찾지 못함 | 비밀번호 해싱 미확인 |
| A04:221 | `f"세션 쿠키 {m} 플래그 미설정"` | 그대로 |
| A04:258 | `f"{loc} {rule} 시크릿 탐지"` | 그대로 |
| A04:274 | 시도할 시크릿 없음(약한 시크릿 목록·소스 추출 모두 비어있음) | 시도할 시크릿 없음 |
| A04:287 | flask 미설치로 세션 위조 검증 불가(정적 weak_default_secret로 감점 유지) | 채점기에 flask 미설치 |
| A04:313 | `f"{origin} 시크릿 {secret!r}로 세션 쿠키를 위조해 user_id={fid}(admin) " f"권한으로 {path} 접근 성공 → 인증 우회·계정 탈취 가능"` | `f"{origin} 시크릿 {secret!r}로 {path} 관리자 접근 성공"` |
| A04:319 | 위조 쿠키 요청에 응답이 없어 판정 불가 | 위조 쿠키 요청 무응답 |

`{origin}`은 "소스에 하드코딩된" 또는 "알려진 약한"이다. 예: `알려진 약한 시크릿 'dev'로 /admin 관리자 접근 성공`

## scoring/checks/A05_injection_csv.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| csv:17 | 관리자 CSV 다운로드(GET /admin/users.csv)를 확인할 수 없음 | /admin/users.csv 다운로드 기능 없음 |
| csv:25 | `f"수식 아이디 가입이 서버 오류({...})라 판정 불가"` | 수식 아이디 가입 무응답 또는 서버 오류 |
| csv:32 | `f"가입한 아이디 {formula!r}가 CSV에 나타나지 않아 판정 불가"` | 가입한 수식 아이디가 CSV에 없음 |
| csv:35 | `f"아이디 {formula!r}가 CSV 셀 맨 앞에 그대로 들어감 → 관리자가 스프레드시트로 열면 수식 실행(CSV Injection)"` | `f"CSV 셀에 수식 {formula!r} 그대로 출력"` |

## scoring/checks/A05_injection_sql.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| sql:45 | `f"{path}:{lineno} 문자열 조합 SQL을 execute()에 전달"` | `f"{path}:{lineno} 문자열 조합 SQL 실행"` |
| sql:205 | sqlmap이 /search 또는 /posts 파라미터에서 SQL 인젝션 확인 → 매개변수 바인딩 미적용 | sqlmap으로 SQL Injection 확인 |
| sql:288 | /search 또는 /posts?sort= 에서 SQL 인젝션 성공 → 매개변수 바인딩 미적용 | SQL Injection 성공 |
| sql:295 | 완전한 인젝션은 아니나 SQL 오류/Stack Trace가 응답에 노출됨 | 응답에 SQL 오류 노출 |
| sql:306 | `f"SQLi 프로브 예외: {exc}"` | `f"검사 중 예외, {exc}"` |

## scoring/checks/A05_injection_xss.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| xss:141 | ``f"{path}:{lineno} render_template_string에 사용자 입력/`\|safe` 사용"`` | `f"{path}:{lineno} render_template_string에 사용자 입력 또는 \|safe 사용"` |
| xss:146 | ``f"{path}:{i} 템플릿 문자열에서 `\|safe` 필터 사용"`` | `f"{path}:{i} 템플릿 문자열에 \|safe 사용"` |
| xss:149 | `f"{path}:{i} autoescape=False 설정"` | 그대로 |
| xss:155 | `f"{path}:{i} \|safe 필터로 자동 이스케이프 우회"` | `f"{path}:{i} \|safe로 이스케이프 우회"` |
| xss:158 | `f"{path}:{i} autoescape false 블록으로 이스케이프 비활성화"` | `f"{path}:{i} autoescape false 블록 사용"` |
| xss:182 | Content-Security-Policy 미설정 → autoescape 우회(속성·JS context) XSS에 무방비. autoescape는 프레임워크 기본값일 뿐 CSP로 스크립트 출처를 제한해야 함 | CSP 미설정 |
| xss:189 | 작성자 세션 없음으로 XSS 판정 불가 | 작성자 세션 없음 |
| xss:222 | `f"{path} 렌더에 XSS 페이로드가 이스케이프 없이 노출됨 → Stored XSS (payload={sig!r})"` | `f"{path}에서 Stored XSS 가능"` |
| xss:240 | `f"/posts/{dpid} 상세 본문 렌더에 XSS 페이로드가 이스케이프 없이 노출 → Stored XSS (payload={dsig!r})"` | `f"/posts/{dpid} 본문에서 Stored XSS 가능"` |
| xss:257 | `f"/posts/{pid} 댓글 렌더에 XSS 페이로드가 이스케이프 없이 노출 → Stored XSS(댓글) (payload={csig!r})"` | `f"/posts/{pid} 댓글에서 Stored XSS 가능"` |
| xss:273 | `f"{path}의 avatar_url이 따옴표 없는 속성에 렌더되어 {attr} 이벤트 핸들러가 주입됨 → Stored XSS"` | `f"{path} avatar_url 속성 탈출로 Stored XSS 가능"` |
| xss:329 | `f"{path} 응답에 입력 페이로드가 이스케이프 없이 반사됨 → Reflected XSS (payload={sig!r})"` | `f"{where}에서 Reflected XSS 가능"` 코드 변경 3 |

## scoring/checks/A06_insecure_design.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| A06:24 | 테스트 계정 없음으로 판정 불가 | 테스트 계정 없음 |
| A06:42 | `f"{attempts}회 실패로는 제한되지 않고 {lax}회 이내에서야 제한됨 " "→ 국내 기준(5회)보다 느슨함(PCI 10회 수준)"` | `f"{attempts}회 실패 후에도 로그인 제한 없음"` |
| A06:46 | `f"{lax}회 연속 로그인 실패 후에도 올바른 비밀번호로 바로 로그인됨 " "→ 인증 실패 횟수 제한(계정 잠금·재시도 지연) 없음"` | `f"{n}회 실패 후에도 로그인 허용"` 코드 변경 4 |
| A06:56 | 로그인 요청에 응답이 없어 판정 불가 | 로그인 요청 무응답 |

A06:42는 50점 부분 감점이다. 같은 결과가 A06:46과 겹치지 않게 "{lax}회 이내 제한"은 증적에 둔다.

## scoring/checks/A07_account_recovery.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| rec:59 | 인증번호 발송(POST /verify/request, 표준출력 VERIFY CODE)을 확인할 수 없음 | 인증번호 발송 확인 불가 |
| rec:65 | 인증번호 확인 요청에 응답이 없어 판정 불가 | 인증번호 확인 요청 무응답 |
| rec:67 | 틀린 인증번호에도 2xx를 돌려줘 성공·실패를 구분할 수 없음 | 틀린 인증번호에도 2xx 응답 |
| rec:70 | 인증번호 확인 요청에 응답이 없어 판정 불가 | 인증번호 확인 요청 무응답 |
| rec:73 | `f"틀린 인증번호 {attempts}회 뒤에도 올바른 번호를 그대로 수락 → 시도 제한 없음 " f"({len(code)}자리 = 최대 {10 ** len(code):,}회 대입으로 인증 우회)"` | `f"인증번호 {attempts}회 오답 후에도 정답 수락"` |
| rec:88 | 새 계정의 로그인 성공과 실패를 구분할 수 없음 | 로그인 성공과 실패 구분 불가 |
| rec:92 | 재설정 요청에 응답이 없음 | 재설정 요청 무응답 |
| rec:95 | 재설정 요청 뒤 표준출력에 RESET TOKEN이 없음 | 재설정 기능 또는 토큰 로그 없음 |
| rec:110 | 재설정 요청 응답에 토큰이 그대로 담겨 그 토큰으로 남의 비밀번호를 바꾸고 로그인함 | 재설정 토큰 노출로 남의 계정 탈취 |
| rec:112 | 재설정 요청 응답에 토큰이 그대로 담김 | 재설정 응답에 토큰 노출 |
| rec:161 | 비밀번호 재설정 요청(POST /password/reset/request) 기능이 없음 | 재설정 기능 없음 |
| rec:163 | 재설정 요청에 응답이 없어 판정 불가 | 재설정 요청 무응답 |
| rec:166 | `f"재설정 요청이 서버 오류({r1.status_code}/{r2.status_code})라 판정 불가"` | 재설정 요청 서버 오류 |
| rec:175 | `f"비밀번호 재설정 요청이 있는 아이디와 없는 아이디에 다르게 응답({diff}) → 계정 존재 여부 노출"` | 재설정 응답으로 계정 존재 여부 노출 |
| rec:188 검사 이름 | 계정 열거 (비밀번호 재설정) | 재설정 계정 열거 |

rec:175의 `{diff}`는 빼도 된다. 증적에 두 응답의 코드와 본문이 이미 있다.

## scoring/checks/A07_authentication_failures.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| auth:57 | `f"{acct.username} 회원가입 요청 실패(무응답) → 기능 게이트"` | `f"{acct.username} 회원가입 무응답"` |
| auth:60 | `f"{acct.username} 회원가입 실패(HTTP {r.status_code}) → 기능 게이트"` | `f"{acct.username} 회원가입 실패 HTTP {r.status_code}"` |
| auth:69 | `f"{acct.username} 로그인 실패({code}) → 기능 게이트"` | `f"{acct.username} 로그인 실패 {code}"` |
| auth:102 | `f"{ctx.userA.username}: 틀린 비밀번호가 수락됨 → 인증 취약"` | `f"{ctx.userA.username} 틀린 비밀번호로 로그인 성공"` |
| auth:118 | `f"userA 게시글 작성 실패({code}) → 기능 게이트"` | `f"userA 글 작성 실패 {code}"` |
| auth:168 | 가입·로그인 요청에 응답이 없거나 서버 오류라 판정 불가 | 가입 또는 로그인 무응답 |
| auth:175 | `f"취약한 비밀번호로 가입·로그인 성공: {', '.join(accepted)} → 비밀번호 작성규칙 미흡"` | `f"약한 비밀번호 허용: {', '.join(accepted)}"` 코드 변경 5 |
| auth:205 | 비번변경·로그아웃 정상 경로를 세우지 못해 세션관리 판정 불가 | 비밀번호 변경과 로그아웃 확인 불가 |
| auth:208 | 비밀번호 변경이 기존 비번을 확인하지 않음(틀린 old_password로도 변경됨) | 기존 비밀번호 확인 없이 변경 가능 |
| auth:210 | 로그아웃 후에도 세션이 인증 상태 유지 — 로그아웃 전 쿠키를 재사용하면 그대로 로그인됨(서버측 세션 무효화 없음) | 로그아웃 후에도 세션 유효 |
| auth:335 | 세션 유효시간 미설정 → Flask 기본 31일 동안 세션 쿠키가 유효(유출·재사용 쿠키가 한 달간 통함) | 세션 유효시간 미설정 |
| auth:340 | `f"세션 유효시간 {minutes:g}분 → 권고(30분 이하)보다 김"` | `f"세션 유효시간 {minutes:g}분, {full:g}분 초과"` 코드 변경 6 |
| auth:342 | `f"세션 유효시간 {minutes:g}분 → 60분 초과(KISA·NIST·PCI 권고 초과)"` | `f"세션 유효시간 {minutes:g}분, {part:g}분 초과"` 코드 변경 6 |
| auth:351 | 관리자 페이지가 익명에게 열려 있어 기본 계정 판정 불가(접근통제 항목에서 판정) | 관리자 페이지 익명 접근 가능 |
| auth:366 | `f"앱이 심어 둔 기본 관리자 계정 {user}/{pw} 로 로그인해 관리자 기능 접근 → 관리자 탈취"` | `f"기본 관리자 계정 {user}/{pw}로 관리자 탈취"` |
| auth:369 | 로그인·관리자 페이지 요청에 응답이 없어 판정 불가 | 로그인 또는 관리자 페이지 무응답 |

## scoring/checks/A08_integrity_failures.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| A08:35 | `f"{path}:{lineno} Insecure Deserialization/동적 실행: {token.strip()}"` | `f"{path}:{lineno} 안전하지 않은 {name} 사용"` 코드 변경 7 |
| A08:82 | 업로더 세션 없음으로 판정 불가 | 업로더 세션 없음 |
| A08:94 | `f"업로드한 HTML이 {url}에서 text/html로 그대로 서빙됨 → Unrestricted File Upload / Stored XSS"` | `f"{url}에서 업로드 HTML 실행 가능"` |
| A08:112 | `f"이미지 서명(GIF89a)을 붙인 HTML이 {url}에서 text/html로 서빙됨 → " "확장자 미검증 업로드 / Stored XSS"` | `f"GIF 서명 붙인 HTML이 {url}에서 실행 가능"` |
| A08:133 | `f"스크립트 가능한 SVG가 {url}에서 image/svg+xml로 인라인 서빙됨 → Stored XSS"` | `f"업로드 SVG가 {url}에서 스크립트 실행 가능"` |
| A08:152 | 업로드 기능 없음/서빙 경로 식별 불가로 판정 불가 | 업로드 기능 또는 서빙 경로 없음 |

## scoring/checks/A09_logging_failures.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| A09:26 | 로깅이 부분적으로만 구성됨(인증/오류 이벤트 기록 미흡) | 보안 로깅 일부만 구성 |
| A09:28 | 보안 로깅/모니터링 구성이 없음 → 침해 탐지 불가 | 보안 로깅 미구성 |

## scoring/checks/A10_exceptional_conditions.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| A10:27 | `f"{method} {path} → Stack Trace/디버거 노출 (디버그 모드/상세 오류)"` | `f"{method} {path} 오류 시 Stack Trace 노출"` |

## scoring/checks/sast.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| sast:45 | `f"{loc} {check_id}"` | 그대로 |

## scoring/engine/runner.py

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| runner:104 | `f"앱 부팅 실패로 동적 검사 불가: {reason}"` | `f"판정 불가: 앱 부팅 실패, {reason}"` |
| runner:196 검사 이름 | 의존성 CVE(실측 전이 포함) | 의존성 CVE |
| runner:197 | `f"CVE 재검사 예외: {exc}"` | `f"CVE 재검사 중 예외, {exc}"` |
| runner:230 | 동적 검사 전체 시간 예산 초과 | 동적 검사 시간 초과 |
| runner:238 | `f"{c.label} 프로브 예외: {exc}"` | `f"{c.label} 검사 중 예외, {exc}"` |

runner:104는 `_undecidable`을 거치지 않아 앞머리를 직접 쓴다.

## config/scoring.yaml critical.repro

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| yaml:107 sqli | sqlmap/부울 차등으로 /search·/login 인젝션 확인 | /search, /posts, /login에 SQL Injection 성공 |
| yaml:108 weak_default_secret | 알려진 시크릿으로 세션 쿠키 서명 위조 → user_id=1(admin)로 /admin 접근 | 알려진 SECRET_KEY로 세션 위조, /admin 접근 |
| yaml:109 hardcoded_secret | 소스에 박힌 SECRET_KEY로 세션 쿠키 서명 위조 → user_id=1(admin)로 /admin 접근 | 소스의 SECRET_KEY로 세션 위조, /admin 접근 |
| yaml:110 access_control_admin | 일반 사용자 세션으로 /admin·/admin/users 직접 접근 | 일반 사용자로 /admin, /admin/users 접근 |
| yaml:111 admin_user_mgmt | 일반 사용자가 POST /admin/users/<자기 id>/role 로 관리자 승격 후 /admin 접근 | 일반 사용자가 자기 역할을 admin으로 변경 |
| yaml:112 privilege_escalation | 가입 요청에 is_admin/role=admin 을 넣어 관리자 계정 생성 | 가입 요청에 is_admin, role 넣어 관리자 생성 |
| yaml:113 default_credentials | admin/admin 등 흔한 기본 계정으로 로그인 → /admin 접근 | admin/admin 같은 기본 계정으로 관리자 로그인 |
| yaml:114 reset_token_leak | 남의 아이디로 재설정 요청 → 응답에 담긴 토큰으로 비밀번호 변경 → 새 비밀번호로 로그인 | 재설정 응답의 토큰으로 남의 비밀번호 변경 |

## config/scoring.yaml critical.severity

| 위치 | 지금 | 바꿀 문장 |
|---|---|---|
| yaml:98 sqli | Critical · SQL Injection · CWE-89 (Top25 #2) · CVSS 9.3 | Critical · SQL Injection · CWE-89 · CVSS 9.3 |
| yaml:99 weak_default_secret | Critical · Session Forgery · CWE-798 · CVSS 9.3 | 그대로 |
| yaml:100 hardcoded_secret | Critical · Session Forgery · CWE-798 · CVSS 9.2 | 그대로 |
| yaml:101 privilege_escalation | Critical · Mass Assignment · CWE-915 · CVSS 9.3 | 그대로 |
| yaml:102 default_credentials | Critical · Default Credentials · CWE-1392 · CVSS 9.3 | 그대로 |
| yaml:103 access_control_admin | High · Missing Authorization · CWE-862 (Top25 #4) · CVSS 8.7 | High · Missing Authorization · CWE-862 · CVSS 8.7 |
| yaml:104 admin_user_mgmt | High · Privilege Escalation · CWE-862 (Top25 #4) · CVSS 8.7 | High · Privilege Escalation · CWE-862 · CVSS 8.7 |
| yaml:105 reset_token_leak | Critical · Weak Password Recovery · CWE-640 · CVSS 9.3 | 그대로 |

Top25 순위는 결과 화면의 `standards` 태그에 이미 있다.

## 코드도 바꿔야 하는 곳

1. A01:248 `sorted(extra)`가 `[...]`로 찍힘. `fields = ", ".join(sorted(extra))`
2. A03:142 `fixed_txt`가 없으면 "N/A 에서 수정됨"이 됨. `fix_note = f"{fixed}에서 수정" if fixed else "수정 버전 없음"`
3. A05_xss:320 가짜 경로 `"/" + payload`가 사유에 그대로 들어가 페이로드의 괄호와 꺾쇠가 찍힘. `where = "/search" if path == "/search" else "404 페이지"`
4. A06:46 시도 횟수가 `lax`로 고정. userB가 없으면 `attempts`회만 시도함. `n = lax if ctx.userB is not None and lax > attempts else attempts`
5. A07_auth:166 `f"{label}({pw!r})"`가 괄호를 만듦. `f"{label} {pw!r}"` 172행 `startswith("8자 미만")`은 그대로 맞음
6. A07_auth:340, 342 30분과 60분이 문장에 박혀 설정값과 어긋날 수 있음. `full`, `part`를 문장에 넣음
7. A08:35 정규식 토큰이 `pickle.loads(`, `eval(`처럼 괄호로 끝남. `name = token.strip().rstrip("( ")`
8. base.py:71 앞머리 변경
9. http.py:398 앞머리 변경
10. external_tools.py:18-20 상수 세 개 변경

## 뜻이 틀린 문장

- A06:46 userB가 없으면 `attempts`회만 시도했는데 `{lax}회`라고 적음. 코드 변경 4로 고침
- A05_sql:288 "/search 또는 /posts?sort=에서"라고 하지만 /login 인증 우회로도 같은 사유가 나옴. "SQL Injection 성공"으로 경로를 뺌
- A05_sql:205, 288 "매개변수 바인딩 미적용"은 코드가 확인하지 않는 추정. 뺌
- A04:170 "솔트·반복 없는 저장"은 확인하지 않음. 해시 함수 호출만 봄. "비밀번호에 빠른 해시 사용"
- A09:26 "인증/오류 이벤트 기록 미흡"은 확인하지 않음. 로깅 설정과 로그 호출 중 하나만 있는지 봄. "보안 로깅 일부만 구성"
- A07_rec:95 경로가 없을 때도 나오는데 "토큰이 없음"만 적음. "재설정 기능 또는 토큰 로그 없음"
- A07_auth:335 `PERMANENT_SESSION_LIFETIME`이 있어도 `timedelta(weeks=1)`처럼 못 읽으면 "미설정"이 됨. 문장은 두고 `_TD_PART`에 weeks를 더하거나 "유효시간 해석 불가"로 따로 냄
- yaml:107 sqli repro가 /search, /login만 적음. sqlmap은 /posts도 봄
- yaml:108, 109 "user_id=1"로 적었지만 UUID 앱이면 userA의 id로 위조함. id를 빼고 적음
