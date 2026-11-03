# OWASP ASVS 5.0.0 · OWASP Top 10:2025 기반 채점 기준 매핑 (check_id ↔ ASVS 요구사항·레벨, 수치 기준, 레벨 가중 제안)

조사일 2026-10-24. 원문은 GitHub 태그 `v5.0.0_release`(ASVS)와 `OWASP/Top10` master `2025/docs/en`(Top 10)에서 직접 받아 읽었다. 저장소 쪽은 `config/scoring.yaml`, `scoring/checks/*.py`, `research_notes/isms-p-criteria/isms_p_mapping.md`(Q4·Q6·Q7)를 대조했다. "(추론)" 표시는 원문에 해당 앱 행위가 명시되지 않아 요구사항 취지로 연결한 경우다.

링크 약어(이 문서 전체에서 사용):
[V1]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x10-V1-Encoding-and-Sanitization.md
[V2]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x11-V2-Validation-and-Business-Logic.md
[V3]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x12-V3-Web-Frontend-Security.md
[V4]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x13-V4-API-and-Web-Service.md
[V5]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x14-V5-File-Handling.md
[V6]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x15-V6-Authentication.md
[V7]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x16-V7-Session-Management.md
[V8]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x17-V8-Authorization.md
[V9]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x18-V9-Self-contained-Tokens.md
[V11]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x20-V11-Cryptography.md
[V12]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x21-V12-Secure-Communication.md
[V13]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x22-V13-Configuration.md
[V14]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x23-V14-Data-Protection.md
[V15]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md
[V16]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md
[AppC]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x92-Appendix-C_Cryptography.md
[What]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x03-What-is-the-ASVS.md
[Chg]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en/0x05-For-Users-Of-4.0.md
[Map]: https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/mappings/mapping_v5.0.0_to_v4.0.3.yml
[T10]: https://github.com/OWASP/Top10/tree/master/2025/docs/en

## Q1. check_id별 ASVS 5.0.0 요구사항 ID·레벨·요지와 OWASP Top 10:2025 범주

### Takeaway
ASVS의 최신 정식판은 5.0.0(2025-05-30)이고, Top 10:2025는 2025-12에 RC 표기를 떼고 정식판이 됐다. 33개 검사 중 ASVS 근거가 없는 것은 `semgrep`(ASVS가 개발 절차를 범위 밖으로 둠)과 `hallucinated_package`(명시 요구 없음, L3 15.2.4로 간접)뿐이다. 국내 근거가 없던 `csp`·`security_headers`·`cookie_flags`의 SameSite·`transport_security`·`typosquatting`은 V3·V12·V15에 근거가 있다. 다만 ASVS 레벨은 위험도 순위가 아니다. `debug_true`, `verbose_errors`, `hardcoded_secret`, `password_hashing`(저장), `ssrf`, mass assignment, 역직렬화는 모두 **L2**이고, 채점기가 치명으로 다루는 항목들도 여기에 들어간다.

### Cited Findings
**버전·구조**
- ASVS 최신 정식 릴리스는 `v5.0.0_release`(2025-05-30 게시)다. 이후 `latest`는 "Bleeding Edge" 개발판(2026-10-15 갱신)이다. — [GitHub Releases](https://github.com/OWASP/ASVS/releases)
- 5.0은 17개 장, 약 350개 요구사항으로 구성된다. ID 형식은 `<chapter>.<section>.<requirement>`이고, 버전을 고정하려면 `v5.0.0-1.2.5`처럼 쓰라고 권장한다. — [What]
- 4.0.3의 286개 요구사항 중 그대로 남은 것은 11개뿐이다. 나머지는 번호가 바뀌었다. 5.0.0의 L1은 345개 중 70개(20%)로 줄었다(4.0.3은 278개 중 128개, 46%). CWE·NIST 직접 매핑은 본문에서 삭제됐다. — [Chg]
- 레벨 정의: L1은 "다른 취약점이나 전제조건 없이 악용 가능한 흔한 공격을 막는 1차 방어선"이다. L2는 "덜 흔한 공격이나 더 복잡한 방어로, 공격 성공에 전제조건이 필요할 수 있음"이다. L3는 "심층 방어 또는 구현이 어려운 통제"다. 레벨은 **위험 감소와 구현 노력의 비교**로 정했다. 비밀번호 관련 요구는 L2부터 MFA가 요구되기 때문에 L1에서 더 중요하게 취급된다. — [What] "Level evaluation", "Level 1/2/3"
- OWASP Top 10:2025 범주: A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures, A10 Mishandling of Exceptional Conditions. — [Top 10:2025 Introduction](https://github.com/OWASP/Top10/blob/master/2025/docs/en/0x00_2025-Introduction.md), [top10.owasp.org/2025](https://top10.owasp.org/2025)
- 2021 대비 변경점: SSRF가 A01로 흡수됐다("Server-Side Request Forgery (SSRF) has been rolled into this category"). A03은 A06:2021(취약·구버전 구성요소)을 공급망 전체로 넓힌 범주다. A10은 신설이다. — 같은 Introduction
- 정식판 시점: index.md 커밋 "Removed RC from ttitle"(2025-12-24)과 "Rename A09 to 'Security Logging & Alerting Failures'"(2025-12-13). — [커밋 이력](https://github.com/OWASP/Top10/commits/master/2025/docs/en/index.md)

**Top 10:2025 CWE 소속**(각 범주 문서의 "List of Mapped CWEs"를 grep으로 확인)
- A01: CWE-352(CSRF), 639(IDOR), 284, 285, 200, 918(SSRF), 1275(SameSite). A02: 489(디버그 코드), 614(Secure 없는 쿠키), 1004(HttpOnly 없음), 260. A03: 1104, 1357. A04: 916(약한 비밀번호 해시), 321(하드코딩 암호키), 319(평문 전송), 330. A05: 89, 79, 20. A06: 434(업로드), 256(평문 자격증명 저장), 269(권한 관리), 693, 1021(클릭재킹). A07: 307(인증 시도 제한), 521(약한 비밀번호), 384(세션 고정), 613(세션 만료), 798(하드코딩 자격증명), 1392(기본 자격증명), 287, 640. A08: 502(역직렬화), 915(mass assignment), 829. A09: 778, 117, 532, 223. A10: 209(오류 메시지 정보노출), 754, 755. — [T10] 각 `A0x_2025-*.md`
- A02 본문은 "server does not send security headers or directives"와 "Error handling reveals stack traces"를 명시한다. A07은 "Reuses the same session identifier after successful login", 로그아웃·유휴 시 세션 미무효화, 계정 열거 방지("same messages for all outcomes")를 명시한다. A01은 "a cookie or hidden field manipulated to elevate privileges"(세션 위조)를 명시한다. — [A02](https://github.com/OWASP/Top10/blob/master/2025/docs/en/A02_2025-Security_Misconfiguration.md), [A07](https://github.com/OWASP/Top10/blob/master/2025/docs/en/A07_2025-Authentication_Failures.md), [A01](https://github.com/OWASP/Top10/blob/master/2025/docs/en/A01_2025-Broken_Access_Control.md)

**매핑표.** ASVS 원문 레벨과 문구는 [V1]~[V16], [AppC]에서, 4.0.3 대응 ID는 공식 매핑 파일 [Map]에서 확인했다. "주"는 실패 판정과 가장 직접 맞는 요구사항이고 "보조"는 관련 요구사항이다. 최고 레벨은 주·보조 중 가장 낮은 숫자, 즉 가장 기본적인 레벨이다.

| check_id | ASVS 5.0.0 주 요구사항 (레벨) — 요지 | 보조 요구사항 (레벨) | 4.0.3 대응 | Top 10:2025 | 최고 레벨 |
|---|---|---|---|---|---|
| sqli | **1.2.4 (L1)** DB 쿼리는 파라미터화·ORM 등으로 SQLi 방지 | — | 5.3.4 (+5.3.5) | A05 (CWE-89) | L1 |
| sql_parameterization | **1.2.4 (L1)** (정적 확인) | — | 5.3.4 | A05 | L1 |
| stored_xss | **1.2.1 (L1)** HTML·속성 등 컨텍스트에 맞는 출력 인코딩 | 3.2.2 (L1) 텍스트는 안전한 렌더링 함수로; 1.2.2 (L1) URL 생성 시 `javascript:`·`data:` 금지; 1.3.1 (L1) WYSIWYG HTML 새니타이즈 | 5.3.1; 3.2.2는 신설(5.3.3에서 분리) | A05 (CWE-79) | L1 |
| reflected_xss | **1.2.1 (L1)** | 1.2.3 (L1) JS·JSON 컨텍스트 인코딩 | 5.3.1 | A05 | L1 |
| xss_template | **1.2.1 (L1)** | 1.1.2 (L2) 인코딩은 인터프리터 직전에; 1.3.7 (L2) 템플릿 인젝션 | 5.3.1 | A05 | L1 |
| csp | **3.4.3 (L2)** CSP 헤더. 최소 `object-src 'none'`, `base-uri 'none'`, 그리고 허용목록 또는 nonce·hash. L3는 응답별 nonce·hash | 3.4.6 (L2) `frame-ancestors`; 3.4.7 (L3) report 위치 | 14.4.3 | A02 (헤더 미전송), A05 심층방어(추론) | L2 |
| csrf_protection | **3.5.1 (L1)** CORS preflight에 의존하지 않으면 anti-forgery 토큰이나 비-safelisted 헤더로 출처 검증 | 3.5.3 (L1) 민감 기능은 POST 등 비안전 메서드로; 3.3.2 (L2) SameSite를 목적에 맞게 | 4.2.2 (+13.2.3) / 13.2.1 / 3.4.3 | A01 (CWE-352, 1275) | L1 |
| unrestricted_upload | **5.2.2 (L1)** 확장자와 내용(매직바이트 등) 일치 검증; **3.2.1 (L1)** 업로드 파일이 잘못된 컨텍스트에서 렌더링되지 않게(Sec-Fetch-*, CSP sandbox, `Content-Disposition: attachment`) | 5.3.1 (L1) 서버측 코드로 실행 금지; 5.3.2 (L1) 경로는 내부 생성값으로; 1.3.4 (L2) SVG 새니타이즈; 5.2.1 (L1) 크기 제한 | 12.2.1 / 12.5.2 / 12.4.1 | A06 (CWE-434) | L1 |
| ssrf | **1.3.6 (L2)** 프로토콜·도메인·경로·포트 허용목록으로 SSRF 방지 | 15.3.2 (L2) 외부 URL 호출 시 리다이렉트를 따라가지 않음; 13.2.4·13.2.5 (L2) 아웃바운드 허용목록; 5.3.2 (L1, 파일 경로발 SSRF) | 5.2.6 | **A01** (CWE-918, 2025에 흡수) | L2 |
| insecure_deserialization | **1.5.2 (L2)** 신뢰할 수 없는 데이터 역직렬화는 타입 허용목록 등으로 제한하고 불안전 메커니즘 사용 금지 | **1.3.2 (L1)** `eval()` 등 동적 코드 실행 회피(채점기는 eval·exec도 탐지함) | 5.5.3 / 5.2.4 | A08 (CWE-502) | L1(eval)·L2(pickle·yaml) |
| idor_profile | **8.2.2 (L1)** 데이터별 접근을 명시 권한자로 제한(IDOR·BOLA); **8.2.3 (L2)** 필드 수준 접근 제한(BOPLA). 비공개 phone 필드가 여기에 해당 | 15.3.1 (L1) 데이터 객체의 필요한 필드만 반환; 14.2.6 (L3) 최소 민감정보만 반환 | 4.2.1 / 8.2.3·15.3.1은 신설 | A01 (CWE-639, 200) | L1 |
| access_control_admin | **8.2.1 (L1)** 기능 수준 접근을 명시 권한자로 제한 | 8.3.1 (L1) 신뢰 계층(서버)에서 인가 | 4.1.3 / 4.1.1 | A01 (CWE-284, 285, force browsing) | L1 |
| admin_user_mgmt | **8.2.1 (L1)** (역할 변경 엔드포인트의 기능 수준 인가) | 8.3.1 (L1); 8.2.2 (L1) 대상 사용자 객체 | 4.1.3 | A01("Elevation of privilege"); CWE-269는 2025 목록에서 A06 소속 | L1 |
| privilege_escalation | **15.3.3 (L2)** mass assignment 방지(액션별 허용 필드 제한) | 8.2.3 (L2) 필드 수준 쓰기 권한; 2.2.1 (L1) 보안 결정에 쓰이는 입력 검증(추론) | 5.1.2 | A08 (CWE-915), A01 권한상승 | L2(엄밀), L1(2.2.1 추론) |
| default_credentials | **6.3.2 (L1)** "root", "admin", "sa" 같은 기본 계정이 없거나 비활성 | 6.4.1 (L1) 시스템 생성 초기 비밀번호는 무작위·단기 | 2.5.4 | A07 (CWE-1392, 1393) | L1 |
| weak_default_secret | **13.3.1 (L2)** 비밀값은 비밀관리 솔루션에 두고 소스·빌드 산출물에 포함 금지 | 11.5.1 (L2) 추측 불가 값은 CSPRNG·128비트 이상; 9.1.1 (L1) self-contained 토큰은 서명·MAC 검증(약한 키는 이를 무력화, 추론) | 6.4.1 / 6.3.1 | A04 (CWE-321, 330); CWE-798은 A07 | L2(직접), L1(9.1.1 추론) |
| hardcoded_secret | **13.3.1 (L2)** 소스 코드에 비밀값 포함 금지 | 11.5.1 (L2) | 6.4.1 (+2.10.4) | A04 (CWE-321) / A07 (CWE-798) / A02 (CWE-260) | L2 |
| session_forgery (증거) | **9.1.1 (L1)** self-contained 토큰은 서명·MAC으로 변조 검증 | 7.2.1 (L1) 세션 토큰 검증은 신뢰 백엔드에서 | (9.1.1은 V3 일부에서 이동) | A01 (쿠키 조작 권한상승) | L1 |
| debug_true | **13.4.2 (L2)** 운영 환경에서 모든 구성요소의 디버그 모드 비활성 | 15.2.3 (L2) 운영 환경에 개발 기능 노출 금지 | 14.3.2 | A02 (CWE-489) | L2 |
| verbose_errors | **16.5.1 (L2)** 예기치 못한 오류에는 일반 메시지만 반환(스택트레이스·쿼리·키 노출 금지) | 13.4.6 (L3) 백엔드 버전 정보 비노출; 16.5.3 (L2) fail-open 금지 | 7.4.1 | **A10** (CWE-209), A02 본문도 언급 | L2 |
| password_hashing | **11.4.2 (L2)** 승인된 계산집약적 KDF(비밀번호 해시 함수)로 저장, 파라미터는 현행 지침 | **11.4.1 (L1)** MD5 등 불허 해시는 어떤 암호 용도로도 금지; 부록 C 파라미터 | 2.4.1 (+2.4.3·2.4.4 병합) | A04 (CWE-916); 평문은 A06 (CWE-256) | L1(MD5·SHA-1 판정), L2(KDF 요구) |
| rate_limiting | **6.3.1 (L1)** 크리덴셜 스터핑·무차별 대입 방어 통제를 문서대로 구현 | 6.1.1 (L1) 레이트리밋·안티오토메이션 문서화, **악의적 계정잠금 방지** 명시; 2.4.1 (L2) 과도한 호출 방지 | 2.2.1 | A07 (CWE-307) | L1 |
| weak_password_policy | **6.2.1 (L1)** 최소 8자(15자 이상 강력 권장); **6.2.4 (L1)** 상위 3000개 흔한 비밀번호 차단 | 6.2.5 (L1) 조합 규칙 강제 금지; 6.2.9 (L2) 64자 이상 허용; 6.2.11 (L2) 문맥 단어 차단; 6.2.12 (L2) 유출 비밀번호 대조 | 2.1.1 / 2.1.7 / 2.1.9 / 2.1.2 | A07 (CWE-521) | L1 |
| auth_session_management | **6.2.3 (L1)** 비밀번호 변경 시 현재·새 비밀번호 모두 요구; **7.4.1 (L1)** 로그아웃·만료 후 세션 사용 불가. self-contained 토큰은 폐기 목록, 사용자별 기준시각, 사용자별 서명키 교체 등이 필요 | 7.4.3 (L2) 비밀번호 변경 후 다른 세션 종료 옵션; 7.5.1 (L2) 전화번호 등 민감 속성 변경 시 재인증 | 2.1.6 / 3.3.1 / 3.3.3 | A07 (CWE-613) | L1 |
| cookie_flags | **3.3.1 (L1)** `Secure` 속성. `__Host-`를 쓰지 않으면 `__Secure-` 접두사 필수 | 3.3.2 (L2) SameSite; 3.3.3 (L2) `__Host-` 접두사; 3.3.4 (L2) HttpOnly | 3.4.1 / 3.4.3 / 3.4.4 / 3.4.2 | A02 (CWE-614, 1004), A01 (CWE-1275) | L1(Secure)·L2(나머지) |
| security_headers | **3.4.1 (L1)** HSTS를 모든 응답에, max-age 1년 이상(L2부터 includeSubDomains) | 3.4.4 (L2) `X-Content-Type-Options: nosniff`; 3.4.6 (L2) CSP `frame-ancestors`. **X-Frame-Options는 "obsolete … may not be relied upon"**; 3.4.5 (L2) Referrer-Policy; 3.4.8 (L3) COOP; 4.1.1 (L1) Content-Type과 charset | 14.4.5 / 14.4.4 / 14.4.7 / 14.4.6 | A02 | L1(HSTS)·L2(나머지) |
| transport_security | **12.2.1 (L1)** 외부 노출 HTTP 서비스는 모두 TLS, 평문 폴백 금지 | 12.1.1 (L1) TLS 1.2·1.3만; 12.2.2 (L1) 공인 인증서; 3.4.1 (L1) HSTS; 4.1.2 (L2) 사용자용 엔드포인트만 HTTP→HTTPS 리다이렉트 | 9.1.1 (+1.9.1) | A04 (CWE-319) | L1 |
| security_logging | **16.3.1 (L2)** 모든 인증 동작(성공·실패) 기록; **16.2.1 (L2)** 각 로그에 when·where·who·what 메타데이터 | 16.3.2 (L2) 인가 실패 기록; 16.2.2 (L2) UTC 또는 오프셋; 16.2.5 (L2) 자격증명 로깅 금지; 16.4.1 (L2) 로그 인젝션 방지 | 7.2.1 / 7.1.4 / 7.2.2 | A09 (CWE-778, 117, 532, 223) | L2 |
| cve | **15.2.1 (L1)** 문서화된 갱신·조치 기한을 넘긴 구성요소가 없음 | 15.1.1 (L1) 취약 구성요소 조치 기한 문서화; 15.1.2 (L2) SBOM | 14.2.1에서 분리(신설) | A03 (CWE-1104) | L1 |
| typosquatting | **15.2.4 (L3)** 모든 의존성(전이 포함)이 예상 저장소에서 오고 dependency confusion 위험이 없음 | 15.1.2 (L2) 신뢰·지속 관리되는 저장소에서 온 구성요소 목록 | 10.3.2 | A03("components from untrusted sources"), A08 (CWE-829) | L3(직접)·L2(간접) |
| hallucinated_package | (명시 요구 없음) 15.2.4 (L3)·15.1.2 (L2)의 취지로 간접 연결(추론) | — | — | A03(추론) | 근거 약함 |
| semgrep | (없음) ASVS는 개발 수명주기 활동을 규정하지 않음: "ASVS does not prescribe development lifecycle activities" | — | — | — | 근거 없음 |
| gitleaks_secrets | **13.3.1 (L2)** 소스·빌드 산출물에 비밀값 포함 금지 | 13.4.1 (L1) `.git` 등 소스관리 메타데이터 미배포 | 6.4.1 / 14.3.3 | A04·A07·A02 | L2 |

**채점기에 없지만 표준이 요구하는 검사**(ISMS-P 노트 Q7 후보와 대조)

| 후보 | ASVS 5.0.0 (레벨) — 요지 | 4.0.3 | Top 10:2025 |
|---|---|---|---|
| session_timeout | 7.3.1 (L2) 유휴 타임아웃, 7.3.2 (L2) 절대 최대 수명. 모두 "위험분석과 문서화된 결정에 따라"이고 **수치는 없다**. 7.1.1 (L2)는 NIST SP 800-63B 재인증 요구에서 벗어나면 그 근거를 문서화하라고 요구한다 | 3.3.2 (L1 30일 / L2 12시간 또는 유휴 30분 / L3 12시간 또는 유휴 15분) | A07 (CWE-613) |
| session_fixation | **7.2.4 (L1)** 인증(재인증 포함) 시 새 세션 토큰을 생성하고 현재 토큰 종료 | 3.2.1 | A07 (CWE-384) |
| login_enumeration | **6.3.8 (L3)** 오류 메시지, HTTP 코드, 응답 시간으로 유효 사용자를 추론할 수 없어야 함(가입·비밀번호 찾기 포함) | 신설 | A07(How to prevent: 동일 메시지) |
| object_authorization (게시글·댓글 수정·삭제) | **8.2.2 (L1)** IDOR·BOLA 방지 | 4.2.1 | A01 (CWE-639) |
| 접속기록 필드 | **16.2.1 (L2)** when·where·who·what; 16.2.2 (L2) UTC·오프셋 | 7.1.4 | A09 |

### Inferences
- 4.0.3에서는 V2 인증, V3 세션, V14 헤더였던 항목이 5.0에서 V6 인증, V7 세션, V3 프런트엔드, V13 설정으로 이동했다. 보고서나 화면에 ID를 표기할 때는 ASVS 권장대로 `v5.0.0-` 접두를 붙여야 혼동이 없다.
- 채점기 파일명은 Top 10:2025 범주를 따르지만 2025 CWE 소속과 어긋나는 곳이 있다. `rate_limiting`은 A06 파일에 있지만 CWE-307은 A07이다. `unrestricted_upload`는 A08 파일에 있지만 CWE-434는 A06이다. `privilege_escalation`은 A01 파일에 있지만 CWE-915는 A08이다. `cookie_flags`는 A04 파일에 있지만 CWE-614·1004는 A02다. 기능상 결과(권한상승)로 분류했다면 A01도 방어할 수 있다. 다만 화면에 "CWE-915 · A01"처럼 함께 표기하면 Top 10 원문과 다르다(`config/scoring.yaml` severity 98행 근처).
- `idor_profile`이 다루는 것은 "타인 프로필 페이지는 볼 수 있어도 phone 필드는 비공개"라는 상황이다. 그래서 ASVS로는 객체 단위 8.2.2(L1)보다 **필드 단위 8.2.3(L2)와 15.3.1(L1)**이 더 정확하다.

### Gaps
- ASVS 5.0.0의 CSV·JSON 산출물은 확인하지 않고 markdown 원문만 읽었다. 레벨 숫자는 markdown 표의 Level 열 그대로다.
- Top 10:2025의 정식 발표일(보도자료 날짜)은 1차 출처에서 찾지 못했다. 저장소 커밋으로 2025-12 정식화만 확인했다.
- OWASP CRE를 통한 ASVS 5.0↔CWE 매핑은 조회하지 않았다. 저장소의 `v5.0.be_cwe_mapping.json`은 bleeding-edge 기준이라 쓰지 않았다.

## Q2. ASVS 5.0이 정한 수치 기준 (비밀번호, 레이트리밋, 세션, 쿠키, 해시, CSP·헤더)

### Takeaway
ASVS 5.0이 **수치를 직접 주는 것**은 다음과 같다. 비밀번호 최소 8자(15자 권장), 최대 64자 이상 허용, 상위 3000개 차단, 조합 규칙 금지. HSTS max-age 1년 이상. CSP 최소 지시어(`object-src 'none'`, `base-uri 'none'`). 해시 파라미터는 부록 C에 있다. **레이트리밋 횟수와 세션 타임아웃은 5.0에서 수치가 빠지고 "문서화된 결정"으로 바뀌었다.** 수치가 필요하면 4.0.3(시간당 100회, L2 12시간/유휴 30분)이나 NIST SP 800-63B-4(100회, AAL2 24시간/유휴 1시간), Session Management Cheat Sheet(유휴 15~30분, 절대 4~8시간)를 써야 한다.

### Cited Findings
| 항목 | ASVS 5.0.0 수치 | 출처 |
|---|---|---|
| 비밀번호 최소 길이 | "at least 8 characters … a minimum of 15 characters is strongly recommended" (6.2.1, L1) | [V6] |
| 비밀번호 최대 길이 | "passwords of at least 64 characters are permitted" (6.2.9, L2) | [V6] |
| 차단 목록 | 가입·변경 시 "at least, the top 3000 passwords" 대조 (6.2.4, L1); 유출 비밀번호 대조 (6.2.12, L2); 문맥 단어 (6.2.11, L2) | [V6] |
| 조합 규칙 | "There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters" (6.2.5, L1) | [V6] |
| 주기적 변경 | "must not require periodic credential rotation" (6.2.10, L2) | [V6] |
| 기타 | type=password 마스킹 (6.2.6 L1), 붙여넣기·비밀번호 관리자 허용 (6.2.7 L1), 잘라내기·대소문자 변환 없이 검증 (6.2.8 L1) | [V6] |
| 레이트리밋 (5.0) | 수치 없음. 6.3.1 (L1)은 "according to the application's security documentation", 6.1.1 (L1)은 "prevent malicious account lockout" 문서화 | [V6] |
| 레이트리밋 (4.0.3, 참고) | 2.2.1 (L1): "no more than 100 failed attempts per hour is possible on a single account" | [ASVS 4.0.3 V2](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x11-V2-Authentication.md) |
| 레이트리밋 (NIST) | 실패 연속 시도 "no more than 100" (SP 800-63B-4 §3.2.2) | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) |
| 세션 유휴·절대 (5.0) | 7.3.1·7.3.2 (L2): "according to risk analysis and documented security decisions". 수치 없음 | [V7] |
| 세션 (4.0.3, 참고) | 3.3.2: L1 "30 days", L2 "12 hours or 30 minutes of inactivity", L3 "12 hours or 15 minutes of inactivity, with 2FA" | [ASVS 4.0.3 V3](https://github.com/OWASP/ASVS/blob/v4.0.3_release/4.0/en/0x12-V3-Session-management.md) |
| 세션 (NIST 800-63B-4) | AAL1 전체 30일 이하(SHOULD), 유휴는 선택. AAL2 전체 24시간·유휴 1시간 이하(SHOULD). AAL3 전체 12시간(SHALL)·유휴 15분(SHOULD) (§2.1.3, 2.2.3, 2.3.3) | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) |
| 세션 (Cheat Sheet) | 유휴 "2-5 minutes for high-value applications and 15-30 minutes for low risk applications", 절대 "between 4 and 8 hours"(사무 업무 예시) | [Session Management CS](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| 세션 종료 | 로그아웃·만료 후 세션 재사용 불가. self-contained 토큰은 폐기 목록, 사용자별 기준시각, 서명키 교체 중 하나가 필요 (7.4.1 L1). 계정 비활성·삭제 시 전 세션 종료 (7.4.2 L1). 인증 요소 변경 후 다른 세션 종료 옵션 (7.4.3 L2). 로그인 시 새 토큰 (7.2.4 L1) | [V7] |
| 세션 토큰 엔트로피 | reference 토큰은 CSPRNG·128비트 이상 (7.2.3 L1). 일반 난수는 128비트 이상 (11.5.1 L2) | [V7], [V11] |
| 쿠키 | Secure + `__Secure-` 또는 `__Host-` 접두사 (3.3.1 L1), SameSite는 목적에 맞게 (3.3.2 L2), `__Host-` (3.3.3 L2), HttpOnly (3.3.4 L2), 이름+값 4096바이트 이하 (3.3.5 L3). **5.0은 SameSite 값을 지정하지 않는다** | [V3] |
| 쿠키 (Cheat Sheet) | "Session cookies must explicitly set `SameSite=Strict` (preferred) or `SameSite=Lax`". SameSite는 CSRF 토큰을 대체하지 않는 심층 방어. `__Host-` 권장 | [Session Management CS](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) |
| 비밀번호 해시 (부록 C, 상태 A=승인) | argon2id: t=1이면 m≥46 MiB, t=2면 m≥19 MiB, t≥3이면 m≥12 MiB (p=1). scrypt: p=1이면 N≥2^17 (128 MiB), p=2면 N≥2^16, p≥3이면 N≥2^15 (r=8). bcrypt cost≥10. PBKDF2-HMAC-SHA-512 ≥210,000회. PBKDF2-HMAC-SHA-256 ≥600,000회. PBKDF2-HMAC-SHA-1 ≥1,300,000회는 L(레거시) | [AppC] "Hash Functions for Password Storage" |
| 해시 (Cheat Sheet) | argon2id m=19 MiB·t=2·p=1, scrypt N=2^17·r=8·p=1, bcrypt ≥10(72바이트 제한), PBKDF2-SHA256 600,000회, **PBKDF2-SHA512 220,000회**. 부록 C(210,000)와 다름 | [Password Storage CS](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| 불허 해시 | MD5는 어떤 암호 용도로도 금지 (11.4.1 L1). MD5·SHA-1 기반 KDF는 D(불허) | [V11], [AppC] |
| HSTS | "A maximum age of at least 1 year … for L2 and up … all subdomains" (3.4.1 L1) | [V3] |
| CSP | "object-src 'none' and base-uri 'none' and defines either an allowlist or uses nonces or hashes". L3는 응답별 nonce·hash (3.4.3 L2). `frame-ancestors` (3.4.6 L2). 위반 보고 (3.4.7 L3) | [V3] |
| 기타 헤더 | nosniff (3.4.4 L2), Referrer-Policy (3.4.5 L2), COOP same-origin (3.4.8 L3), CORS ACAO는 고정값 또는 허용목록 (3.4.2 L1), 응답 Content-Type과 charset (4.1.1 L1), `Cache-Control: no-store` (14.3.2 L2) | [V3], [V4], [V14] |

**Flask·Python 기본값과의 대조**(1차 소스코드 확인)
- Flask: `PERMANENT_SESSION_LIFETIME = timedelta(days=31)`, `SESSION_COOKIE_NAME = "session"`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SECURE = False`, `SESSION_COOKIE_SAMESITE = None`. — [flask/app.py](https://github.com/pallets/flask/blob/main/src/flask/app.py)
- Flask 쿠키 세션의 `open_session`은 `permanent` 여부와 무관하게 `max_age = permanent_session_lifetime`으로 서명 타임스탬프를 검증한다(`s.loads(val, max_age=max_age)`). 따라서 기본값이면 **탈취·재사용된 쿠키가 31일간 유효**하다. ISMS-P 노트 Q5 Gap이 검증 필요로 남긴 내용을 이것으로 확인했다. — [flask/sessions.py](https://github.com/pallets/flask/blob/main/src/flask/sessions.py)
- Werkzeug `generate_password_hash`의 기본 method는 `scrypt:32768:8:1`(N=2^15, r=8, p=1)이다. pbkdf2 기본 반복 횟수는 `DEFAULT_PBKDF2_ITERATIONS = 1_000_000`(pbkdf2:sha256)이다. — [werkzeug/security.py](https://github.com/pallets/werkzeug/blob/main/src/werkzeug/security.py) (최신 릴리스 3.1.9, 2026-09-27)
- argon2-cffi 기본값은 RFC 9106 LOW_MEMORY(t=3, m=64 MiB, p=4)다. — [argon2-cffi profiles.py](https://github.com/hynek/argon2-cffi/blob/main/src/argon2/profiles.py). pyca/bcrypt `gensalt(rounds=12)`. — [bcrypt __init__.pyi](https://github.com/pyca/bcrypt/blob/main/src/bcrypt/__init__.pyi)

### Inferences
- **Werkzeug 기본 scrypt(N=2^15, p=1)는 ASVS 5.0 부록 C의 scrypt 최소값(p=1이면 N≥2^17)에 못 미친다.** Password Storage CS(N=2^17)와도 어긋난다. 반면 `method="pbkdf2"`(1,000,000회 ≥ 600,000), bcrypt 기본 12(≥10), argon2-cffi 기본(t=3에서 64 MiB ≥ 12 MiB)은 충족한다. argon2의 p=4는 부록 C 표가 p=1만 적고 있어 직접 판정할 수 없다. 메모리 조건은 넘으므로 충족으로 본다(추론).
- Flask 기본 31일은 NIST AAL1 상한(30일)과 4.0.3 L1(30일)보다 길다. ASVS 5.0 자체에는 수치가 없으므로 "ASVS 위반"이라고 하면 안 되고, "ASVS 7.1.1이 참조하는 NIST 기준 초과"로 표현하는 것이 정확하다.
- 레이트리밋을 국제 기준만으로 판정하면 "100회 이내 차단"이 상한이다. 현행 5회(`config/scoring.yaml` 540~546행)는 국내 기준(고시 제5조⑥ 해설 "예: 5회")에서 온 것이고 국제 기준보다 엄격하다. ASVS 5.0과 충돌하지는 않는다. 다만 6.1.1의 "악의적 계정잠금 방지"를 고려하면 영구 잠금보다 지연·임시 잠금을 우선 인정하는 현행 판정(지연도 통과)이 ASVS 취지와 맞는다.

### Gaps
- ASVS 5.0이 세션 타임아웃 수치를 삭제한 공식 이유(토론 이슈)는 찾지 않았다. [Chg]의 "NIST 결합도 완화" 설명에서 추정할 뿐이다.
- PBKDF2-SHA512 반복 횟수가 부록 C(210,000)와 Cheat Sheet(220,000)에서 다른 이유는 확인하지 못했다.

## Q3. ASVS 레벨을 가중치에 반영하는 방안

### Takeaway
ASVS 레벨은 "위험 감소 대비 구현 노력"으로 정해진다. 그래서 심각도 축으로 쓰면 RCE급인 `debug_true`(L2)가 쿠키 Secure(L1)보다 가벼워지는 역전이 생긴다. 따라서 레벨은 **"모든 앱이 갖춰야 할 기본선(L1)" 가산점**으로만 쓴다. 국내 공식 `w = R + L + I`에 작은 항 `A`(L1 +1, L2 +0.5, L3 0)를 더하고, 국내 근거가 전혀 없는 검사에만 ASVS 레벨로 R을 대체하는 방식을 제안한다.

### Cited Findings
- 레벨은 "comparing risk reduction with the effort to implement the requirement"로 정하며, 1차 방어선인지 심층 방어인지를 함께 고려한다. — [What] "Level evaluation"
- L1은 "first-layer of defense requirements for preventing common attacks that do not require other vulnerabilities or preconditions"다. L2는 "may require certain preconditions for the attack to be successful"이다. L3는 "defense-in-depth mechanisms or other useful but hard-to-implement controls"다. — [What]
- 5.0은 "risk-based levels that mandate a specific level"이 경직적이었다고 보고 조직이 목표 레벨을 고르게 했다. — [Chg] "Not Just About Risk"
- 현행 국내 공식과 산출값(R: CIIP 위험도·SW 보안약점, L: 고시 직접 의무 +2, I: ISMS-P 명시 +1)은 다음과 같다. idor_profile·access_control_admin·admin_user_mgmt 6, privilege_escalation 5, rate_limiting 6, password_hashing 5, security_logging 5, csp 0~1, security_headers 1, typosquatting·hallucinated_package·semgrep·transport_security 0. — `research_notes/isms-p-criteria/isms_p_mapping.md` Q6(b). 현재 `config/scoring.yaml` 19~53행과 344행 이후에 반영돼 있다.

### Inferences
**(a) 제안 공식(설계안)**

`w = R + L + I + A`

- **A (ASVS 기본선 가산)**: 그 검사의 *실패 조건*이 위반하는 ASVS 요구사항 중 가장 낮은 레벨 기준으로 L1 +1, L2 +0.5, L3 또는 없음 0을 준다. A의 상한을 1로 둬서 국내 법적 의무 L(+2)보다 작게 한다. 국제 기준은 국내 법정 기준을 보완할 뿐 뒤집지 않는다.
- **국내 근거가 없는 검사(R=L=I=0)**: 위 A 대신 `R_asvs`(L1 2, L2 1, L3 0.5)를 R 자리에 쓴다. 다만 **샌드박스에서 판정할 수 없는 요구사항은 레벨과 무관하게 0**으로 둔다. HTTP 샌드박스에서의 HSTS와 TLS가 그 예다. 계약·채점기가 부과한 제약을 감점하지 않는다는 오탐 최소화 원칙에 따른 것이다.
- 정적·동적이 같은 요구사항을 나누는 비율(동적 2 : 정적 1)은 ISMS-P 노트 Q6 규칙을 유지한다.

**(b) 산출 예(현행 w에 A를 더함)**

| check | 현행 w (국내) | ASVS 최고 레벨 → A | 제안 w |
|---|---|---|---|
| idor_profile | 6 | L1 (8.2.2·15.3.1) +1 | 7 |
| access_control_admin | 6 | L1 (8.2.1) +1 | 7 |
| admin_user_mgmt | 6 | L1 (8.2.1) +1 | 7 |
| privilege_escalation | 5 | L2 (15.3.3) +0.5 | 5.5 |
| SQLi 항목(sqli+sql_parameterization) | 3 | L1 (1.2.4) +1 | 4 → 2.67 : 1.33 |
| XSS 항목(stored+reflected+template) | 3 | L1 (1.2.1) +1 | 4 → 1.6 : 1.6 : 0.8 |
| unrestricted_upload | 3 | L1 (5.2.2·3.2.1) +1 | 4 |
| csrf_protection | 3 | L1 (3.5.1) +1 | 4 |
| ssrf | 2 | L2 (1.3.6) +0.5 | 2.5 |
| insecure_deserialization | 2 | L1 (1.3.2 eval) / L2 (1.5.2) → +0.5~1 | 2.5~3 |
| password_hashing | 5 | L1 (11.4.1, MD5 판정) +1 | 6 |
| weak_default_secret | 4 | L2 (13.3.1·11.5.1) +0.5 | 4.5 |
| hardcoded_secret | 3 | L2 +0.5 | 3.5 |
| cookie_flags | 2 | L1 (3.3.1 Secure) +1 | 3 |
| rate_limiting | 6 | L1 (6.3.1) +1 | 7 |
| weak_password_policy | 4 | L1 (6.2.1·6.2.4) +1 | 5 |
| default_credentials | 4 | L1 (6.3.2) +1 | 5 |
| auth_session_management | 3 | L1 (6.2.3·7.4.1) +1 | 4 |
| verbose_errors | 4 | L2 (16.5.1) +0.5 | 4.5 |
| debug_true | 4 | L2 (13.4.2) +0.5 | 4.5 |
| cve | 1 | L1 (15.2.1) +1 | 2 |
| security_logging | 5 | L2 (16.3.1·16.2.1) +0.5 | 5.5 |
| security_headers | 1 | HSTS L1은 판정 불가로 제외, nosniff·frame-ancestors L2 → R_asvs 1 | 1~1.5 |
| csp | 0~1 | L2 (3.4.3) → R_asvs 1 | 1 |
| transport_security | 0 | L1이지만 HTTP 샌드박스에서 판정 불가 → 0 | 0 (보고 전용) |
| typosquatting | 0 | L3 (15.2.4) → 0.5 | 0~0.5 (보고 전용 권장) |
| hallucinated_package | 0 | 명시 요구 없음 → 0 | 0 (보고 전용) |
| semgrep | 0 | ASVS 범위 밖 → 0 | 0 |
| (신규) object_authorization | 4 | L1 (8.2.2) +1 | 5 |
| (신규) session_fixation | 3 | L1 (7.2.4) +1 | 4 |
| (신규) session_timeout 사용자/관리자 | 4 / 6 | L2 (7.3.1·7.3.2) +0.5 | 4.5 / 6.5 |
| (신규) login_enumeration | 4 | L3 (6.3.8) 0 | 4 |
| (신규) 접속기록 필드 | security_logging에 포함 | L2 (16.2.1) | — |

- 효과: 국내 서열은 그대로 두고 **L1 기본기**(CSRF, 업로드, 레이트리밋, 기본 계정, 비밀번호 정책, 로그아웃 무효화, 쿠키 Secure, CVE)를 L2 항목(SSRF, 역직렬화, 디버그, 오류 노출, 헤더·CSP)보다 반 단계 올린다. 치명 감점(`critical.penalties`)은 실증 피해 기준이므로 ASVS 레벨로 조정하지 않는다. 레벨이 심각도가 아니기 때문이다.
- 대안(혼합하지 않는 방식): 가중치는 국내 공식으로 두고, 화면에 **"ASVS L1 기본선 충족률"**을 별도 지표로 보인다. 채점기가 판정할 수 있는 L1 요구사항 중 통과한 비율을 쓴다. 대상은 1.2.1, 1.2.4, 3.5.1, 5.2.2/3.2.1, 6.2.1, 6.2.3, 6.2.4, 6.3.1, 6.3.2, 7.2.4, 7.4.1, 8.2.1, 8.2.2, 11.4.1, 15.2.1이다. 점수 체계를 건드리지 않으면서 국제 기준 근거를 보여 줄 수 있어 부스 설명용으로 더 단순하다.

### Gaps
- A 항의 크기(+1/+0.5)와 R_asvs(2/1/0.5)는 ASVS가 정한 값이 아니라 설계상 선택이다. ASVS는 레벨별 점수나 가중치 개념을 두지 않는다([What]에 레벨 = 목표 성숙도로만 정의).

## Q4. 국내 기준이 다루지 않는 검사의 ASVS 근거, 그리고 ASVS 5.0과 충돌하는 채점기 동작

### Takeaway
ASVS는 국내 근거가 없던 CSP(3.4.3 L2), XCTO(3.4.4 L2), 클릭재킹(3.4.6 L2, 단 XFO는 "obsolete"), HSTS(3.4.1 L1), SameSite(3.3.2 L2), mass assignment(15.3.3 L2), 역직렬화(1.5.2 L2), SSRF(1.3.6 L2, 15.3.2 리다이렉트 미추종), 의존성 출처(15.2.4 L3)에 근거를 준다. 충돌은 다섯 가지다. 첫째, `csrf_protection`이 SameSite만으로 만점을 준다. 둘째, `security_headers`가 X-Frame-Options를 점수로 인정한다. 셋째, `csp`가 지시어 내용 없이 존재만으로 만점을 준다. 넷째, `password_hashing`이 Werkzeug 기본 scrypt(N=2^15)를 강한 KDF로 본다. 다섯째, HSTS는 존재만 보고 max-age(1년)를 보지 않는다. 반대로 `auth_session_management`의 쿠키 재사용 검사와 `weak_password_policy`의 "조합 규칙 미요구"는 ASVS 5.0과 정확히 맞는다.

### Cited Findings
**국내에 없던 검사의 ASVS 근거**
- CSP: 3.4.3 (L2) 최소 `object-src 'none'`, `base-uri 'none'`, 허용목록이나 nonce·hash. 3.4.6 (L2) `frame-ancestors`로 기본 임베드 금지. "the X-Frame-Options header field, although supported by browsers, is obsolete and may not be relied upon." — [V3]
- 보안 헤더: HSTS 3.4.1 (L1, 1년 이상), nosniff 3.4.4 (L2), Referrer-Policy 3.4.5 (L2), COOP 3.4.8 (L3). — [V3]
- 전송 보안: 12.2.1 (L1) 외부 노출 서비스 전부 TLS·평문 폴백 금지, 12.1.1 (L1) TLS 1.2·1.3. — [V12]
- SameSite: 3.3.2 (L2) 목적에 맞게 설정해 "browser-based request forgery" 노출을 줄인다. CSRF의 주 요구사항은 3.5.1 (L1) anti-forgery 토큰 또는 비-safelisted 헤더다. — [V3]
- Mass assignment: 15.3.3 (L2) 액션별 허용 필드 제한. — [V15]
- 역직렬화: 1.5.2 (L2). eval 계열은 1.3.2 (L1). — [V1]
- SSRF: 1.3.6 (L2) 허용목록. 15.3.2 (L2) 외부 URL 호출 시 의도된 경우가 아니면 리다이렉트 미추종. 13.2.4·13.2.5 (L2) 아웃바운드 허용목록. — [V1], [V15], [V13]
- 공급망: 15.2.1 (L1) 조치 기한을 넘긴 취약 구성요소 없음, 15.2.4 (L3) 예상 저장소·dependency confusion 위험 없음. Top 10 A03은 "components from untrusted sources"와 OSV 모니터링을 명시한다. — [V15], [A03](https://github.com/OWASP/Top10/blob/master/2025/docs/en/A03_2025-Software_Supply_Chain_Failures.md)
- 업로드 렌더링 컨텍스트: 3.2.1 (L1) 사용자 업로드 파일이 직접 요청될 때 잘못된 컨텍스트로 렌더링되지 않게 한다(CSP sandbox, `Content-Disposition: attachment` 등). — [V3]

**채점기 현행 동작(저장소)**
- `csrf_protection`(정적)은 CSRF 토큰·Flask-WTF가 있거나 `SESSION_COOKIE_SAMESITE`/`samesite=`가 `Lax|Strict`이면 보호로 판정한다. — `scoring/checks/A01_broken_access_control.py` 37~52행; `config/scoring.yaml` 405행
- `security_headers`(정적)는 CSP, X-Frame-Options, HSTS, X-Content-Type-Options 문자열을 각 25점으로 센다. `transport_security`(동적)도 같은 4개 헤더와 쿠키 3속성을 센다. — `scoring/checks/A02_security_misconfiguration.py` 39~41, 53~110행; `config/scoring.yaml` 398행
- `csp`(정적)는 `Content-Security-Policy`, `Talisman(` 등의 문자열만 있으면 `score_present` 100점을 준다. — `scoring/checks/A05_injection_xss.py` 168~185행. 반면 XSS 동적 보조 함수 `_csp_blocks_inline_script`는 `unsafe-inline` 여부를 실제로 파싱한다(같은 파일 20~40행).
- `password_hashing`(정적)은 `bcrypt|argon2|scrypt|pbkdf2|generate_password_hash|…`가 있으면 strong(100)으로 본다. 약한 해시는 `md5|sha1(`만 본다. — `scoring/checks/A04_cryptographic_failures.py` 117~120, 133~165행
- `cookie_flags`는 HttpOnly·Secure·SameSite만 본다. `__Host-`·`__Secure-` 접두사는 보지 않는다. 동적 프로브는 Secure 쿠키를 HTTP 샌드박스에서 쓸 수 있게 `_desecure`로 Secure 플래그를 지운다. — `scoring/checks/A04_cryptographic_failures.py` 168~213행; `scoring/shared/http.py` 165~173행
- `weak_password_policy`는 7자(`Abc12!x`), 숫자만 8자(`12345678`), 아이디와 동일한 비밀번호를 거부하는지 본다. 조합 규칙은 요구하지도 감점하지도 않는다. — `config/scoring.yaml` 547~556행
- `security_logging`은 로깅 설정과 logger 호출이 있는지만 정적으로 확인한다. — `scoring/checks/A09_logging_failures.py` 17~30행

### Inferences
**ASVS 5.0과 충돌하거나 어긋나는 동작**
1. **CSRF와 SameSite (부분 충돌).** ASVS 5.0은 SameSite를 3.3.2(L2, 노출 감소)로 두고 CSRF 차단의 주 요구사항(3.5.1 L1)을 토큰이나 비-safelisted 헤더로 정의한다. Session Management CS도 SameSite를 "defense in depth, not a replacement"로 본다. SameSite=Lax만 있는 앱에 100점을 주는 것은 ASVS 문언보다 관대하다. 현실에서 Lax는 교차 사이트 폼 POST를 막으므로 실증 피해는 작다. 그래서 권고는 "SameSite만 있으면 부분 점수(예: 60~70), 토큰이 있으면 100"이다(설계안). 동적 CSRF 실증(외부 출처 POST 성공 시 치명)은 그대로 둔다.
2. **X-Frame-Options 가점 (충돌).** 3.4.6은 XFO를 "obsolete … may not be relied upon"이라고 명시한다. 클릭재킹 항목은 CSP `frame-ancestors`로 판정하고, XFO는 동등 대체가 아니라 0.5배 인정이나 증거로만 쓰는 편이 ASVS와 맞는다. `security_headers`와 `csp`가 CSP를 이중 계산하는 문제도 함께 정리할 만하다.
3. **CSP 존재만 판정 (불완전).** 3.4.3의 최소 조건(`object-src 'none'`, `base-uri 'none'`, 허용목록 또는 nonce·hash)을 보지 않아 `default-src *`나 `'unsafe-inline'`만 있는 정책도 만점을 받는다. 동적 응답 헤더 파싱(이미 `_csp_blocks_inline_script`가 있음)으로 바꾸고 단계 점수를 주는 것을 제안한다. 예: 존재 40, `unsafe-inline` 없음 +30, object-src·base-uri +30(설계안).
4. **Werkzeug 기본 scrypt를 strong으로 인정 (파라미터 미달).** `generate_password_hash()` 기본값(scrypt N=2^15, r=8, p=1)은 부록 C의 p=1 최소 N=2^17에 미달한다. 다만 이것은 프레임워크 기본값이고, 국내 기준(SHA-224 이상·솔트)은 넉넉히 충족한다. 그래서 감점하지 말고 보고서에 "ASVS 부록 C 권장 파라미터 미달" 참고 문구만 붙이거나, 95점 수준의 미세 차등만 두는 것이 오탐 최소화 원칙과 맞다(추론). 반대로 `hashlib.sha256(salt+pw)`처럼 KDF가 아닌 단일 SHA-2는 국내 고시는 충족하지만 ASVS 11.4.2(L2)는 위반한다. 현행 정규식에서는 이 경우 strong·weak 어느 쪽에도 걸리지 않아 `score_unknown`(30, `config/scoring.yaml` 364행)으로 떨어진다. 결과적으로 MD5(30)와 같은 점수다(`A04_cryptographic_failures.py` 116~120, 133~165행 확인). 또 `pbkdf2:sha256:1000`처럼 반복 횟수를 낮춘 호출도 `pbkdf2` 문자열만으로 strong이 된다. 즉 부록 C 파라미터는 어떤 방향으로도 검사하지 않는다.
5. **HSTS max-age 미검사.** 3.4.1은 max-age 1년 이상을 요구한다. 다만 HTTP 샌드박스에서 HSTS는 의미가 없으므로 점수에서 빼고 보고만 하는 것이 일관적이다(Q3 판정 불가 원칙).
6. **쿠키 접두사.** 3.3.1(L1)은 `__Secure-`/`__Host-` 접두사를 요구하고, Flask 기본 이름 `session`은 이를 위반한다. 그러나 `__Host-`는 Secure 쿠키라서 HTTP 샌드박스에서는 브라우저 기준으로 동작하지 않는다(채점기는 `_desecure`로 우회). 감점하면 채점 환경이 부과한 제약을 감점하는 셈이므로 가점이나 참고로만 처리할 것을 권한다.
7. **레이트리밋 임계값.** 5회는 국내 기준이고 ASVS 5.0은 수치가 없으며 4.0.3·NIST의 상한은 100회다. 충돌은 아니다. 다만 화면 문구에 "ASVS 기준 5회"처럼 쓰면 사실과 다르다.

**ASVS 5.0과 잘 맞는 동작(근거 강화)**
- `auth_session_management`의 로그아웃 후 쿠키 재사용 검사: 7.4.1(L1)이 self-contained 토큰(Flask 쿠키 세션이 여기에 해당)은 폐기 목록, 사용자별 기준시각, 서명키 교체가 없으면 불충분하다고 명시한다. Flask 기본 `session.clear()`만으로는 이를 충족하지 못한다. 기존 비밀번호 확인은 6.2.3(L1)과 정확히 맞는다.
- `weak_password_policy`: 6.2.1(8자), 6.2.4(상위 3000개, `12345678` 포함으로 추론), 6.2.5(조합 규칙 금지)와 일치한다. 64자 허용(6.2.9 L2) 검사를 추가할 수 있다. 예: 64자 비밀번호로 가입하고 로그인이 되는지 확인한다. 이 검사는 거부해도 보안상 피해가 없으므로 오탐 위험이 낮다.
- `ssrf`가 공개 주소에서 사설 주소로 가는 302를 쓰는 프로브는 15.3.2(L2, 리다이렉트 미추종)와 직접 대응한다.
- `default_credentials`는 6.3.2(L1)가 "admin" 계정을 예시로 든 그대로다.

**신규 검사에 대한 ASVS 시사점**
- `login_enumeration`은 ASVS에서 **L3**(6.3.8)다. 국내 기준(ISMS-P 2.5.3 사례 2)보다 낮게 평가된다. 응답 시간 차이까지 요구하므로, 채점기는 메시지·상태 코드 차이만 판정하고 시간 차이는 보고만 하는 것이 오탐을 피한다(추론).
- `session_fixation`은 L1(7.2.4)이다. Flask 쿠키 세션은 로그인 시 쿠키 값이 바뀌지만, 로그인 전 쿠키가 서명이 유효한 채로 남는다. 판정은 "로그인 전 세션 데이터가 로그인 후에도 유지되는가"와 "로그인 전 쿠키로 인증 상태가 되는가"로 한정해야 한다(추론, ISMS-P 노트 Q7과 같은 결론).
- `session_timeout`은 ASVS 5.0에 수치가 없다. 국제 수치 근거는 NIST AAL1 30일과 AAL2 유휴 1시간·전체 24시간이다. Flask 기본 31일은 AAL1 상한을 넘으므로 "설정 없음 = 미흡" 판정의 국제 근거가 된다.

### Gaps
- `password_hashing`에서 솔트 있는 SHA-256(국내 고시 충족, ASVS 11.4.2 위반)을 몇 점으로 둘지는 표준 간 판단이 갈린다. 국내는 100, ASVS는 미흡이다. 이번 조사로는 결정 근거를 더 좁히지 못했다.
- OWASP CSRF Prevention Cheat Sheet의 SameSite 관련 원문은 직접 확인하지 않았다. SameSite가 심층 방어라는 판단은 Session Management Cheat Sheet 인용에 근거한다.
- `top 3000` 목록에 `12345678`이 들어 있다는 점은 일반 상식(모든 흔한 비밀번호 목록 상위)에 따른 추론이다. ASVS는 특정 목록을 지정하지 않는다.
