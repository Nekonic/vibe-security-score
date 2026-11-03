# MITRE CWE Top 25(2025판) + CVSS v4.0/v3.1 기반 check별 심각도 차등안

> 작성일: 2026-10-24. 대상: Flask + sqlite3 게시판 채점기의 check_id.
> 목적: 국내 표준이 웹 항목을 모두 "상"으로 평가해서 검사 간 차등이 없다. 국제 기준(CWE 순위, CVSS 점수, 버그바운티 등급)으로 심각도를 나눈다.
> 표기: "(추론)"은 출처가 직접 말하지 않고 필자가 판단한 내용이다. CVSS 벡터는 모두 이 앱에서 나타나는 형태를 기준으로 필자가 평가한 값이다. 점수는 RedHat `cvss` 파이썬 라이브러리 3.6으로 계산했다([GitHub](https://github.com/RedHatProductSecurity/cvss)). 계산 전에 이 라이브러리가 FIRST 공식 예제 벡터 9개의 점수를 그대로 재현하는지 확인했다(아래 Q2 참고). 표기법은 FIRST 규칙에 따라 Base 지표만 쓴 점수를 **CVSS-B**로 적는다.

## Q1. 2026-10 기준 최신 CWE Top 25 판과, 관련 CWE의 정확한 순위·점수

### Takeaway
2026-10-24 기준 최신판은 **2025 CWE Top 25**다(페이지 최종 갱신 2025-12-15). 2026년판은 아직 나오지 않았다. 2026-01-29에 보조 목록 두 개가 공개됐다. 하나는 순위 26~40을 담은 "On the Cusp" 목록이고, 다른 하나는 KEV 기반 "Top 10 KEV Weaknesses"다. 이 채점기와 관련된 CWE 중 Top 25에 든 것은 79(1위), 89(2위), 352(3위), 862(4위), 22(6위), 94(10위), 434(12위), 502(15위), 863(17위), 284(19위), 200(20위), 918(22위), 639(24위)다. 인증·세션·암호·설정 계열 CWE는 대부분 Top 40 밖이다.

### Cited Findings
**판 정보·방법론**
- 2025 Top 25 페이지의 "Page Last Updated"는 December 15, 2025다. — [CWE 2025 Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- 데이터셋은 2024-06-01부터 2025-06-01 사이에 공개된 CVE 레코드 **39,080건**이다. 점수 공식은 `Score = Fr(CWE) × Sv(CWE) × 100`이다. Fr은 정규화한 빈도이고, Sv는 정규화한 평균 CVSS 기본점수다. 심각도에는 버전 간 산식 차이 때문에 **CVSS v3.0/v3.1 기본점수만** 쓰고, v4는 언급하지 않는다. — [2025 Methodology](https://cwe.mitre.org/top25/archive/2025/2025_methodology.html)
- 2026년 CWE 뉴스에 2026 Top 25 발표는 없다. 2026년 항목은 다음과 같다.
  - 2026-01-29: 2025 Top 10 KEV와 2025 "On the Cusp" 공개
  - 2026-04-30: CWE 4.20 공개
  - 2026-10-05: CWE 5.0과 Schema 8.0(호환성이 깨지는 변경 포함)을 **2026-10-28**에 공개한다는 예고

  — [CWE News 2026](https://cwe.mitre.org/news/archives/news2026.html)
- 2024판은 2023-06-01부터 2024-06-01 사이의 CVE 31,770건을 썼다. — [Help Net Security](https://helpnetsecurity.com/?p=317410)(2차 출처)

**관련 CWE의 2025 순위·점수(KEV 건수)와 2024 대비**

| CWE | 이름(요약) | 2025 순위 / 점수 / KEV | 2024 순위 / 점수 | 관련 check |
|---|---|---|---|---|
| 79 | XSS | **1 / 60.38 / 7** | 1 / 56.92 | stored_xss, reflected_xss, unrestricted_upload |
| 89 | SQL Injection | **2 / 28.72 / 4** | 3 / 35.88 | sqli |
| 352 | CSRF | **3 / 13.64 / 0** | 4 / 19.57 | csrf_protection |
| 862 | Missing Authorization | **4 / 13.28 / 0** | 9 / 10.11 | access_control_admin, admin_user_mgmt |
| 22 | Path Traversal | **6 / 8.99 / 10** | 5 / 12.74 | (해당 검사 없음. 업로드 파일명, file:// SSRF와 인접) |
| 94 | Code Injection | **10 / 7.57 / 7** | 11 / 7.13 | debug_true(결과), insecure_deserialization(eval) |
| 434 | Unrestricted Upload | **12 / 6.87 / 4** | 10 / 10.03 | unrestricted_upload |
| 502 | Deserialization | **15 / 5.23 / 11** | 16 / 5.07 | insecure_deserialization |
| 863 | Incorrect Authorization | **17 / 4.14 / 4** | 18 / 4.05 | admin_user_mgmt |
| 284 | Improper Access Control | **19 / 4.07 / 1** | (없음) | access_control_admin(현행 yaml 표기) |
| 200 | Sensitive Info Exposure | **20 / 4.01 / 1** | 17 / 5.07 | idor_profile(결과), verbose_errors(부모) |
| 306 | Missing Authn for Critical Function | **21 / 3.47 / 11** | 25 / 2.73 | (인접: 관리자 기능) |
| 918 | SSRF | **22 / 3.36 / 0** | 19 / 4.05 | ssrf |
| 639 | Authz Bypass via User-Controlled Key | **24 / 2.62 / 0** | (Top 25 밖) | idor_profile |

— [CWE 2025 Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html), [CWE 2024 Top 25](https://cwe.mitre.org/top25/archive/2024/2024_top25_list.html)

**2025 "On the Cusp"(26~40위)에 든 관련 CWE**
- 269 Improper Privilege Management: **29위 / 2.08 / KEV 4**. 2024년에는 15위(5.22)였다.
- 287 Improper Authentication: **31위 / 2.04**. 2024년에는 14위(5.94)였다.
- 288 Auth Bypass Using Alternate Path: 33위 / 1.87 / KEV 6
- 798 Use of Hard-coded Credentials: **35위 / 1.59 / KEV 2**. 2024년에는 22위(3.46)였다.
- 601 Open Redirect: 40위 / 1.41

— [2025 On the Cusp](https://cwe.mitre.org/top25/archive/2025/2025_onthecusp_list.html), [2024 Top 25](https://cwe.mitre.org/top25/archive/2024/2024_top25_list.html)

**2025 Top 10 KEV Weaknesses (KEV 기반 목록)**

| 순위 | CWE | KEV 건수 | 점수 |
|---|---|---|---|
| 1 | 78 OS Command Injection | 20 | 80.43 |
| 2 | 416 | 14 | 51.89 |
| 3 | 787 | 12 | 50.39 |
| 4 | 306 | 11 | 50.27 |
| 5 | **502 Deserialization** | 11 | 46.31 |
| 6 | **22 Path Traversal** | 10 | 36.96 |
| 7 | **94 Code Injection** | 7 | 26.62 |
| 8 | 288 | 6 | 22.31 |
| 9 | 122 | 6 | 20.25 |
| 10 | **79 XSS** | 7 | 17.99 |

CWE-89, 352, 862, 918, 639는 KEV Top 10에 들지 않았다. — [2025 KEV list](https://cwe.mitre.org/top25/archive/2025/2025_kev_list.html)

**2025 Top 25와 On the Cusp(Top 40) 모두에 없는 CWE**
다음 CWE는 두 페이지에서 확인되지 않았다.
- 209, 489, 215
- 256, 916, 328, 759
- 915, 1392, 1394, 321
- 521, 307, 620, 384, 613
- 614, 1004, 1275
- 693, 1021, 778
- 1104, 937, 1395

— [2025 Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html), [On the Cusp](https://cwe.mitre.org/top25/archive/2025/2025_onthecusp_list.html)

### Inferences
- **check별 대표 CWE 제안(추론).** 필자의 매핑이다. Bugcrowd VRT→CWE 매핑과 대조했다.

| check_id | 대표 CWE | 보조 CWE |
|---|---|---|
| sqli | 89 | |
| stored_xss | 79 | 83(따옴표 없는 속성 탈출, `javascript:` 스킴) |
| reflected_xss | 79 | |
| csrf_protection | 352 | |
| unrestricted_upload | 434 | 79(실제 결과는 저장형 XSS) |
| ssrf | 918 | 73/22(file:// 로컬 파일 읽기) |
| insecure_deserialization | 502 | 95/94(eval) |
| idor_profile | 639 | 862, 200 |
| access_control_admin | **862** | 425(강제 브라우징) |
| admin_user_mgmt | 862 | 863, 269 |
| privilege_escalation | 915(mass assignment) | 269 |
| default_credentials | 1392(기본 자격증명) | 798 |
| weak_default_secret | **1394**(Use of Default Cryptographic Key) | 321, 798 |
| hardcoded_secret | 321(Hard-coded Cryptographic Key) | 798 |
| session_forgery | 565/345(서명 위조, 증거 전용) | |
| debug_true | 489(Active Debug Code) | 94(결과), 215 |
| verbose_errors | 209 | 200의 자식 |
| password_hashing | 256(평문) | 916, 328, 759(무솔트) |
| rate_limiting | 307 | |
| weak_password_policy | 521 | |
| auth_session_management | 620(Unverified Password Change) | 613 |
| cookie_flags | 1004(HttpOnly) | 614(Secure), 1275(SameSite) |
| security_headers | 693 | 1021(XFO), 319(HSTS) |
| csp | 693 | 1021(frame-ancestors) |
| security_logging | 778 | 223 |
| cve | 1395(Dependency on Vulnerable Third-Party Component) | 1104, 937 |

- **access_control_admin의 CWE 표기 변경 권고(추론).** 현행 `config/scoring.yaml`은 CWE-284를 쓴다. CWE-284는 19위(4.07)이고 상위 추상 개념이다. CWE-862를 쓰면 4위(13.28)이고, "일반 사용자가 관리자 화면에 도달"하는 현상에 더 정확히 맞는다.
- **privilege_escalation의 CWE 표기(추론).** 현행 표기 CWE-915는 Top 40 밖이다. 결과 기준으로 CWE-269(29위)를 보조로 함께 표기하면 순위 근거를 줄 수 있다.
- **CWE 순위만으로 가중치를 매기면 안 된다(추론).** Top 25 점수는 "CVE 빈도 × 평균 CVSS"다. 그래서 XSS(1위)는 신고 건수가 많아 높고, 영향은 더 크지만 CVE로 덜 등록되는 기본 자격증명(1392)이나 기본 암호키(1394)는 순위에 없다. 순위는 **흔한 정도(prevalence)의 근거**로만 쓰고, 심각도는 CVSS와 VRT로 정하는 편이 맞다.
- CWE 5.0이 2026-10-28에 공개될 예정이므로, 반영 시점에 ID나 이름이 바뀌었는지 재확인해야 한다.

### Gaps
- 2025판 페이지에서 CWE별 NVD 매핑 건수(빈도 원값)는 추출하지 못했다. 점수와 KEV 건수만 있다.
- 1392, 1394, 1395, 620의 정식 이름과 존재 여부는 cwe.mitre.org 개별 정의 페이지로 이번에 재검증하지 않았다(필자 지식 기반).
- 2026판이 2026-11~12월에 나올 가능성은 있지만, 예고 자료는 찾지 못했다.

## Q2. check별 CVSS v4.0 기본 벡터·점수(v3.1 교차)와 심각도 등급

### Takeaway
같은 "상"이라도 앱에서 나타나는 형태로 CVSS를 매기면 크게 네 층으로 갈린다.
- **9.x Critical**: 비인증 관리자 장악이나 RCE. sqli, privilege_escalation, default_credentials, weak_default_secret, hardcoded_secret, debug_true, insecure_deserialization
- **7~8.x High**: 로그인한 사용자가 관리자로 올라가거나 개인정보를 대량 노출하는 경우. access_control_admin, admin_user_mgmt, idor_profile, 앱 맥락의 stored_xss, 내용을 돌려주는 ssrf
- **4~6.x Medium**: 피해자 클릭이 필요하거나 영향이 제한적인 경우. reflected_xss, unrestricted_upload, csrf, password_hashing
- **Low/None**: 단독으로 악용할 수 없는 하드닝 항목. cookie_flags, security_headers, csp, security_logging

v4.0은 영향이 Low인 하드닝 항목을 v3.1보다 높게 매기는 경향이 있다(예: cookie_flags 6.3 대 3.7). 그래서 하드닝 계열은 Bugcrowd VRT 우선순위(P4/P5)로 등급을 보정해야 한다.

### Cited Findings
**CVSS v4.0 규칙(FIRST)**
- 정성 등급: None 0.0, Low 0.1~3.9, Medium 4.0~6.9, High 7.0~8.9, Critical 9.0~10.0. 등급 사용은 선택 사항이다. — [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)
- UI 지표
  - **Passive**: 악성 콘텐츠가 렌더링되는 페이지를 이용하는 것 같은 비자발적 상호작용. 스펙은 대부분의 저장형 XSS와 CSRF를 예로 든다.
  - **Active**: 반사형 XSS나 self-XSS처럼 특정 문자열을 제출하는 의도적 행동.
  - 반사형 XSS와 CSRF처럼 사회공학이 필요한 취약점은 보통 PR:None이다.

  — [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)
- 취약 시스템 밖의 영향은 Subsequent(SC/SI/SA)에 매기고, 밖으로 영향이 없으면 N으로 둔다. Base만 쓴 점수는 CVSS-B, Threat를 더하면 CVSS-BT, Threat와 Environmental을 모두 더하면 CVSS-BTE로 표기해야 한다. 규제 요구나 평판 영향은 CVSS 범위 밖이다. — [CVSS v4.0 Specification](https://www.first.org/cvss/v4.0/specification-document)

**FIRST v4.0 공식 예제(벡터 → 점수)**
아래 예제는 필자가 쓴 라이브러리로 모두 같은 점수가 재현됐다. Dolibarr 8.5, PrestaShop 7.1, authentik 9.3, Bosch 8.2, Cisco 7.7, CSRF 5.1을 직접 확인했다.

| 예제 | CVE | v4.0 벡터 | 점수 |
|---|---|---|---|
| Reflected XSS (Zimbra) | CVE-2022-24682 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` | 5.1 |
| Stored XSS (SharePoint) | CVE-2020-0926 | `AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` | 5.1 |
| XSS with expanded impact (Dolibarr) | CVE-2024-55228 | `AV:N/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:L/SI:L/SA:N` | 8.5 |
| CSRF (WordPress plugin) | CVE-2023-5602 | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` | 5.1 |
| SQLi (PrestaShop) | CVE-2023-30545 | `PR:L/UI:N/VC:H/VI:N/VA:N` | 7.1 |
| Auth bypass (authentik) | CVE-2023-48228 | `PR:N/VC:N/VI:H/VA:N/SC:H/SI:H/SA:H` | 9.3 |
| 평문 자격증명 전송 (Bosch) | CVE-2021-23846 | `AT:P/VC:H` | 8.2 |
| 권한상승 (Cisco ASA) | CVE-2022-20759 | `AT:P/PR:L/VC:H/VI:H/VA:H` | 7.7 |

예제 해설의 요지는 다음과 같다.
- XSS의 취약 시스템(웹앱)은 VC/VI/VA:N으로 두고, 피해자 브라우저를 Subsequent(SC/SI:L)로 본다.
- 스크립트가 피해자 권한으로 앱을 조작하면(Dolibarr) VC/VI가 High로 올라간다. 예제는 이 판단이 사용자 권한에 달려 있다고 경고한다.
- CSRF는 앱 자체의 무결성(VI:L)으로 매긴다.

— [FIRST CVSS v4.0 Examples](https://www.first.org/cvss/v4.0/examples)

**Bugcrowd VRT (릴리스 2026-07-08) 우선순위와 공식 CVSS v3 매핑**
P1이 가장 심각하고 P5는 정보성이다. "varies"는 VRT가 우선순위를 고정하지 않은 항목이다.

| VRT 항목 | 우선순위 | VRT 공식 v3 매핑 벡터 → 필자 계산 점수 |
|---|---|---|
| Server-Side Injection > SQL Injection | **P1** | `C:H/I:L/A:N` → 8.2 |
| Server-Side Injection > RCE | P1 | `C:H/I:H/A:H` |
| Server Security Misconfiguration > Using Default Credentials | **P1** | `C:H/I:H/A:L` → 9.4 |
| Broken Authentication > Authentication Bypass | P1 | |
| Exposed Portal > Admin Portal | P1 | |
| IDOR > Modify/View Sensitive Information (Iterable) | P1 | |
| IDOR > View Sensitive Information (Iterable) | **P3** | |
| XSS > Stored > Non-Privileged User to Anyone | **P2** | `S:C/C:H/I:H` → 10.0 |
| XSS > Stored > CSRF/URL-Based | P3 | |
| XSS > Reflected > Non-Self | **P3** | `S:C/C:L/I:L` → 6.1 |
| CSRF > Application-Wide | **P2** | `UI:R/C:H/I:H/A:L` → 8.3 |
| CSRF > Action-Specific > Authenticated Action | varies | |
| SSRF > Internal Secrets Exposure | P2 | `S:C/C:H/I:L` → 9.3 |
| SSRF > Internal Data Exposure | P3 | |
| SSRF > Internal Port Scan Only | P4 | |
| SSRF > External – DNS Query Only | P5 | |
| Insecure Data Storage > Server-Side Credentials Storage > Plaintext | **P4** | `AC:H/PR:H/C:H/I:L` → 5.0 |
| Weak Hash > Lack of Salt | varies | |
| No Rate Limiting on Form > Login | **P4** | `C:L/I:L` → 6.5 |
| No Password Policy | P4 | → 4.2 |
| Weak Password Policy | P5 | |
| Failure to Invalidate Session > On Logout (Client and Server-Side) | **P4** | → 3.8 |
| Failure to Invalidate Session > On Password Reset and/or Change | P4 | |
| Missing Secure or HTTPOnly Cookie Flag > Session Token | **P4** | `AC:H/C:L` → 3.7 |
| Lack of Security Headers (CSP, HSTS, XFO, XCTO 각각) | **P5** | 전체 `C:N/I:N/A:N` → 0.0 |
| Clickjacking > Sensitive Click-Based Action | P4 | |
| Visible Detailed Error/Debug Page > Descriptive Stack Trace | **P5** | |
| Visible Detailed Error/Debug Page > Detailed Server Configuration | P4 | |
| Exposed Debug or Admin Interfaces | varies | `S:C/C:H/I:H/A:H` → 10.0 |
| Cloud Security > Disabled or Insufficient Logging | **P5** | |
| Using Components with Known Vulnerabilities > Outdated Software Version | **P5** | |
| Unsafe File Upload > File Extension Filter Bypass | P5 | |
| Privilege Escalation | varies | |

VRT의 CWE 매핑은 다음과 같다. SQLi→89, XSS→79, CSRF→352, SSRF→918/441, Default Credentials→255/521, Plaintext storage→256, Lack of Salt→759/916, Session Fixation→384, Failure to Invalidate→613, Cookie flag→614/1004, Login rate limit→307, Password policy→521, Privilege Escalation→269.

— [Bugcrowd VRT JSON](https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/master/vulnerability-rating-taxonomy.json), [VRT→CVSS v3 매핑](https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/master/mappings/cvss_v3/cvss_v3.json), [VRT→CWE 매핑](https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/master/mappings/cwe/cwe.json)

### Inferences
**check별 평가표(벡터는 필자 평가, 점수는 라이브러리로 계산).** 공통 전제는 다음과 같다.
- 공격 경로는 인터넷(AV:N)이다.
- 취약 시스템은 Flask 앱과 그 DB이고, Subsequent 시스템은 피해자 브라우저나 내부망이다.
- 가입이 열려 있어서 "로그인한 공격자"는 누구나 될 수 있다. 그래도 CVSS 규칙상 계정이 필요하면 PR:L로 둔다.

| check_id | 대표 CWE (2025 순위) | CVSS v4.0 벡터 (CVSS-B) | v4.0 | v3.1 벡터 | v3.1 | VRT | 권고 등급 |
|---|---|---|---|---|---|---|---|
| sqli | 89 (#2) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` | **9.3** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | 9.1 | P1 | **Critical** |
| (sqli, 로그인 후에만 도달) | | `…PR:L…VC:H/VI:H/VA:N…` | 8.6 | `PR:L … C:H/I:H/A:N` | 8.1 | | High |
| privilege_escalation | 915 (밖) / 269 (#29) | `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N` | **9.3** | `…PR:N…C:H/I:H/A:L` | 9.4 | varies | **Critical** |
| default_credentials | 1392 (밖) / 798 (#35) | 위와 동일 | **9.3** | 위와 동일 | 9.4 | P1 | **Critical** |
| weak_default_secret | 1394 (밖) / 798 (#35) | 위와 동일 | **9.3** | 위와 동일 | 9.4 | P1 (Auth Bypass) | **Critical** |
| hardcoded_secret | 321 (밖) / 798 (#35) | `…AT:P/PR:N/UI:N/VC:H/VI:H/VA:L…` | **9.2** | `AC:H/PR:N … C:H/I:H/A:L` | 7.7 | P1 (Auth Bypass) | **Critical**(위조 실증 시) |
| debug_true | 489 (밖) / 94 (#10) | PIN 해제: `…AT:N/PR:N/UI:N/VC:H/VI:H/VA:H…` / PIN 활성: `…AT:P…` | **9.3 / 9.2** | `C:H/I:H/A:H` 9.8 / `AC:H` 8.1 | 9.8 / 8.1 | varies (v3 매핑 10.0) | **Critical** |
| insecure_deserialization | 502 (#15, KEV #5) | `…PR:N/UI:N/VC:H/VI:H/VA:H…` (PR:L이면 8.7) | **9.3** | `…C:H/I:H/A:H` | 9.8 (PR:L 8.8) | P1 (RCE) | **Critical**(라이브), 정적이면 High |
| access_control_admin | 862 (#4) | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N` | **8.7** | `PR:L … C:H/I:H/A:L` | 8.3 | P1 (Admin Portal) | **High** |
| (조회만 가능할 때) | | `…PR:L…VC:H/VI:N/VA:N…` | 7.1 | `C:H/I:N/A:N` | 6.5 | | High |
| admin_user_mgmt | 862 (#4) / 863 (#17) | `…PR:L/UI:N/VC:H/VI:H/VA:L…` | **8.7** | `PR:L … C:H/I:H/A:L` | 8.3 | varies | **High** |
| stored_xss (앱 맥락) | 79 (#1) | `AV:N/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:N/SC:L/SI:L/SA:N` | **8.5** | `PR:L/UI:R/S:C/C:H/I:H/A:N` | 8.7 | P2 | **High** |
| (FIRST 관례: 브라우저 영향만) | | `…PR:L/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` | 5.1 | `PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 | | Medium |
| (`javascript:` 링크, 클릭 필요) | | `…PR:L/UI:A/…/SC:L/SI:L…` | 4.8 | 위와 동일 | 5.4 | P3 (URL-based) | Medium |
| idor_profile | 639 (#24) / 200 (#20) | `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N` | **7.1** | `PR:L … C:H/I:N/A:N` | 6.5 | P3 (View, iterable) | **High** (VC:L로 보면 5.3 Medium) |
| ssrf (내부 응답 반환) | 918 (#22) | `…PR:L/UI:N/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N` | **6.3** | `PR:L/S:C/C:H/I:L/A:N` | 8.5 | P2~P3 | **High** (v3.1 기준) |
| (file:// 로컬 파일 읽기) | 918 + 22 | `…VC:H/VI:N/VA:N/SC:H/SI:L/SA:N` | 8.4 | 위와 동일 | 8.5 | P2 | High |
| (블라인드, 콜백만 확인) | | `…VC:N…/SC:L/SI:L/SA:N` | 5.3 | `S:C/C:L/I:L` | 6.4 | P4 | Medium |
| csrf_protection (앱 전역) | 352 (#3) | `AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N` | **7.4** | `AC:H/UI:R … C:H/I:H/A:N` | 6.8 | P2 (App-Wide) | **High~Medium** |
| (FIRST 관례: 단일 동작) | | `…AT:N/PR:N/UI:A/VC:N/VI:L/VA:N…` | 5.1 | `UI:R … I:L` | 4.3 | varies | Medium |
| reflected_xss | 79 (#1) | `AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` | **5.1** | `PR:N/UI:R/S:C/C:L/I:L/A:N` | 6.1 | P3 | **Medium** |
| unrestricted_upload (HTML/SVG inline) | 434 (#12) + 79 | `…PR:L/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N` | **4.8** | `PR:L/UI:R/S:C/C:L/I:L/A:N` | 5.4 | (Stored XSS로 분류, P2~P3) | **Medium** |
| password_hashing (평문/MD5) | 256·916·328 (밖) | `AV:N/AC:L/AT:P/PR:H/UI:N/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N` | **5.9** | `AC:H/PR:H/S:C/C:H/I:N/A:N` | 5.8 | P4 | **Medium** |
| rate_limiting | 307 (밖) | `…AT:P/PR:N/UI:N/VC:L/VI:L/VA:N…` | 6.3 | `AC:H … C:L/I:L` (VRT 매핑 6.5) | 4.8 | P4 | **Medium~Low** |
| verbose_errors | 209 (밖) / 200 (#20) | `…AT:N/PR:N/UI:N/VC:L/VI:N/VA:N…` | 6.9 | `C:L/I:N/A:N` | 5.3 | P5 (stack trace) | **Low** (VRT 우선) |
| weak_password_policy | 521 (밖) | `AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N…` | 6.3 | `AC:H/UI:R … C:L/I:L` | 4.2 | P4~P5 | **Low** |
| auth_session_management | 620·613 (밖) | `…AT:P/PR:N/UI:N/VC:L/VI:L/VA:N…` | 6.3 | `PR:H … C:L/I:L` (VRT 매핑) | 3.8 | P4 | **Low** |
| cookie_flags | 1004·614·1275 (밖) | `AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N…` | 6.3 | `AC:H … C:L/I:N/A:N` | 3.7 | P4 | **Low** |
| security_headers | 693·1021 (밖) | XFO 클릭재킹 가정: `…UI:A/VC:N/VI:L/VA:N…` 5.1 / 단독 영향 없음: 0.0 | 0.0~5.1 | `C:N/I:N/A:N` (VRT 매핑) | 0.0 | P5 | **Low** |
| csp | 693 (밖) | 단독 영향 없음 | **0.0** | 0.0 | 0.0 | P5 | **None~Low** (심층방어) |
| security_logging | 778 (밖) | 악용 불가 | **0.0** | 0.0 | 0.0 | P5 | **None** (컴플라이언스 항목) |
| session_forgery | (증거) | weak_default_secret / hardcoded_secret과 동일 사건 | — | — | — | — | 증거 전용(별도 점수 없음) |
| cve | 1395 (밖) / 1104 | 해당 CVE의 NVD 점수를 그대로 상속 | 가변 | 가변 | 가변 | P5 (버전만) | NVD 등급 상속 |

**지표 선택 근거(요약)**
- **PR (비인증 대 로그인).** default_credentials, weak_default_secret, privilege_escalation(가입 단계)은 계정이 없어도 성립하므로 PR:N이다. access_control_admin, admin_user_mgmt, idor_profile, ssrf(link_url은 글 작성 시 입력), stored_xss, upload는 로그인한 사용자가 필요하므로 PR:L이다. sqli는 로그인 폼이나 공개 검색에서 터지면 PR:N이고, 로그인 후에만 닿으면 PR:L(8.6)이다. 채점 프로브가 어느 엔드포인트에서 확인했는지에 따라 고르면 된다(추론).
- **관리자 장악의 VA:L.** 관리자는 글이나 사용자를 삭제할 수 있지만 서비스를 다운시키지는 못한다고 보고 VA:L로 뒀다(추론). RCE(debug, deserialization)는 프로세스를 장악하므로 VA:H다.
- **stored_xss를 High로 둔 이유.** 게시판에서는 관리자를 포함한 모든 사용자가 글을 열람한다(UI:P). 스크립트는 앱 출처에서 피해자 권한으로 실행되므로 CSRF 토큰 탈취, 비밀번호 변경, 역할 변경이 가능하다. FIRST의 Dolibarr "expanded impact" 예제 논리에 따라 VC/VI:H로 봤다(8.5). 보수적으로 FIRST 기본 관례(5.1)를 쓰는 선택지도 있다. Flask 세션 쿠키는 기본이 HttpOnly여서 쿠키 직접 탈취는 막히지만 같은 출처 요청 위조는 가능하다(추론).
- **csrf를 AT:P로 둔 이유.** Chrome 계열은 SameSite 속성이 없는 쿠키를 Lax로 취급하므로 교차 사이트 POST가 기본적으로 차단된다. 그래서 공격 성공에 조건이 붙는다고 보고 AT:P로 뒀다(추론). 반대로 이 앱은 auth_session_management 실패(기존 비밀번호 없이 비밀번호 변경)와 결합하면 계정 탈취가 되므로 VC/VI:H로 뒀다. VRT도 "Application-Wide" CSRF를 P2로 높게 본다.
- **hardcoded_secret / debug_true를 AT:P로 둔 이유.**
  - hardcoded_secret: 공격자가 소스를 확보해야 한다. 반면 `dev`, `secret` 같은 알려진 기본값(weak_default_secret)은 추측만으로 되므로 AT:N이다.
  - debug_true: Werkzeug 디버거 콘솔은 기본적으로 PIN으로 보호된다. PIN이 꺼져 있으면 AT:N, 켜져 있으면 PIN 계산에 필요한 정보 유출이 있어야 하므로 AT:P다(추론).
  - v4에서는 AT:P가 0.1점만 낮추지만 v3.1에서는 AC:H로 1.7점 차이가 난다.
- **password_hashing.** 저장 방식 결함은 DB가 먼저 유출돼야 악용된다(AT:P, PR:H). 비밀번호 재사용 때문에 다른 서비스에 피해가 가므로 SC:L을 줬다. 이 앱처럼 sqli와 함께 나오면 실질 위험이 크게 오른다. 이 결합 효과는 Environmental이나 체인으로 처리해야 한다(추론).
- **하드닝 항목의 v4 과대평가.** v4.0에서 VC:L 하나만 있어도 비인증·저복잡도면 6.9, AT:P면 6.3이 나온다. v3.1에서는 각각 5.3과 3.7이다. VRT도 이 항목들을 P4~P5로 둔다. 그래서 cookie_flags, weak_password_policy, auth_session_management, verbose_errors는 **v4 점수 대신 v3.1 또는 VRT로 등급을 정하는 것**이 과대 감점을 막는다(추론, 위 계산값으로 관찰한 결과).
- **"단독으로 악용 불가" 항목.** CVSS는 악용 가능한 취약점을 평가하는 체계라서 CSP나 로깅 부재처럼 다른 취약점을 전제로 하는 약점은 0.0이 자연스럽다. VRT 공식 매핑도 Lack of Security Headers를 `C:N/I:N/A:N`(0.0)으로 둔다.

**최종 권고 등급 요약(추론)**
- **Critical (9.0+)**: sqli, privilege_escalation, default_credentials, weak_default_secret, hardcoded_secret(위조 실증), debug_true, insecure_deserialization(라이브 실증. 정적 탐지만 있으면 High)
- **High (7.0~8.9)**: access_control_admin, admin_user_mgmt, stored_xss, idor_profile, ssrf(내부 응답 반환 또는 file://), csrf_protection(앱 전역 + 비밀번호 변경 결합)
- **Medium (4.0~6.9)**: reflected_xss, unrestricted_upload, password_hashing, ssrf(블라인드), rate_limiting
- **Low (0.1~3.9)**: verbose_errors, weak_password_policy, auth_session_management, cookie_flags, security_headers
- **None/Info**: csp, security_logging, session_forgery(증거)
- **가변**: cve는 해당 CVE의 NVD 등급을 그대로 쓴다.

**현행 `config/scoring.yaml` 치명 티어와 비교(추론)**
- T1(20~25점)에 넣은 항목 중 access_control_admin과 admin_user_mgmt는 CVSS로 8.7 High다. PR:L이 필요해서 비인증 Critical(9.3)보다 한 단계 낮다. CVSS와 맞추려면 T1 안에서 sqli, default_credentials, weak_default_secret, privilege_escalation, debug_true를 25로, 로그인이 필요한 관리자 계열 둘을 20으로 차등하는 방안이 있다.
- T2의 idor_profile(15)과 stored_xss(15)는 CVSS High(7.1/8.5)와 일치한다. unrestricted_upload(12)는 v4 4.8 Medium으로, reflected_xss(10, 5.1)와 같은 층이다. 그래서 12점을 10점으로 내리는 근거가 있다.
- T3의 ssrf(10)는 내부 응답을 반환하거나 file://이 되면 v3.1 8.5 High이므로 12~15점으로 올릴 근거가 있다. 블라인드면 현행 유지가 맞다. csrf(6)는 VRT P2(App-Wide)와 v4 7.4를 보면 과소평가로 보인다.
- 비치명 가중치 측면에서는 security_headers, csp, security_logging이 CVSS 0.0 / VRT P5다. 국내 표준(Q6) 결론과 마찬가지로 가중치를 최소로 두는 것이 국제 기준과도 일치한다.

### Gaps
- NVD에서 개별 유사 CVE(예: Werkzeug 디버거 CVE-2024-34069, Flask 기본 SECRET_KEY 사례)의 공식 벡터는 이번 조사에서 직접 가져오지 못했다. 위 표의 실제 CVE 근거는 FIRST 예제 문서에 실린 CVE로 한정된다.
- FIRST 예제 문서 후반부(10만 자 이후)에 SSRF, 역직렬화, 기본 자격증명 예제가 있는지는 읽지 못했다.
- v4.0이 Low 영향 항목을 v3.1보다 높게 매긴다는 관찰은 필자 계산에서 나온 것이다. 이 현상을 다룬 공식 FIRST 문서는 찾지 못했다.
- 프로브가 sqli를 로그인 전 엔드포인트에서 확인하는지는 코드에서 확인하지 않았다. PR 값은 이에 따라 달라진다(9.3 대 8.6).

## Q3. 다른 채점기·벤치마크가 CVSS/심각도를 감점 점수로 바꾸는 방식과 선례

### Takeaway
"심각도 등급 → 고정 점수"로 바꾸는 선례는 여러 개 있다.
- **Bugcrowd**: P1~P5에 kudos 40/20/10/5/0을 준다. 한 등급 오를 때마다 2배다.
- **Mozilla HTTP Observatory**: 100점에서 시작해 항목별 고정 감점을 한다.
- **Veracode**: 0~100점이며, 심각도 5단계에 비선형 가중을 하고 같은 등급의 결함이 늘수록 추가 감점이 줄어든다.
- **HackerOne**: CVSS 3.0/3.1/4.0 중 선택하게 하고, 심각도를 바운티 구간에 연결한다. 단 고정 수치 표는 공개하지 않는다.

이 채점기의 현행 cve 감점(critical 40 / high 25 / medium 10 / low 3)은 Bugcrowd의 2배 체계와 비슷한 비선형 구조다.

### Cited Findings
- **Bugcrowd kudos.** 유효 보고의 kudos는 P1 40, P2 20, P3 10, P4 5, P5 0이다. 중복 보고는 P1 10, P2 5, P3 이하 0이다. 우선순위는 VRT를 따르고 최종 결정은 프로그램 소유자가 한다. — [Bugcrowd Docs: Earning Rewards](https://docs.bugcrowd.com/researchers/receiving-rewards/getting-rewarded/) (검색 요약 기준), [Bugcrowd blog: Vulnerability prioritization](https://www.bugcrowd.com/blog/vulnerability-prioritization-at-bugcrowd/)
  - 블로그는 각 등급을 이렇게 설명한다. P1은 RCE 같은 결함, P2는 플랫폼 전역 영향, P3는 여러 사용자에게 상호작용 없이 영향, P4는 단일 사용자 영향, P5는 악용 불가 약점이다.
  - 2015년 글에는 P1 20, P2 15로 되어 있어 값이 바뀌었다. 위 값은 현행 문서 기준이다.
- **VRT→CVSS v3 공식 매핑 파일.** Bugcrowd는 VRT 항목마다 CVSS v3 벡터를 매핑한 파일을 공개한다. 우선순위와 CVSS를 함께 쓸 수 있다는 선례다. — [VRT cvss_v3 mapping](https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/master/mappings/cvss_v3/cvss_v3.json)
- **HackerOne.** 연구자는 None/Low/Medium/High/Critical을 직접 고르거나 CVSS 계산기를 쓴다. 계산기는 CVSS 3.0(커스텀), 3.1, 4.0을 제공하고 프로그램이 조합해서 쓸 수 있다. 자산 단위의 environmental 지표와 최대 심각도를 반영한다. 2026-09-21부터 Bug Bounty, VDP, Challenge 프로그램에서 심각도 입력이 필수다. 심각도는 "바운티 구간을 구성하는 데 특히 유용"하다고 하지만, 등급별 금액이나 점수 표는 공개하지 않는다. — [HackerOne Docs: Severity](https://docs.hackerone.com/en/articles/8495674-severity)
- **Mozilla HTTP Observatory.** 기본 100점에서 감점(1라운드)한 뒤, 감점 후 점수가 90 이상일 때만 가산점(2라운드)을 준다. 최저 0점, 최고 145점이다. 등급은 A+ 100 이상 ~ F 0~24다. 문서는 감점 폭이 업계 의견에 기반하지만 "essentially arbitrary"(본질적으로 임의적)하다고 스스로 밝힌다. — [MDN Observatory: Tests & Scoring](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring)
  - 소스 코드상 감점값은 다음과 같다. — [mdn-http-observatory `src/grader/charts.js`](https://github.com/mdn/mdn-http-observatory/blob/main/src/grader/charts.js)

| 항목 | 감점 |
|---|---|
| 세션 쿠키 Secure 없음 | **−40** |
| 세션 쿠키 HttpOnly 없음 | **−30** |
| CSP 미구현 | **−25** |
| CSP에 unsafe-inline | −20 |
| CSP에 unsafe-eval | −10 |
| 쿠키 Secure 없음 | −20 |
| anti-CSRF 쿠키에 SameSite 없음 | −20 |
| HSTS 미구현 | −20 |
| XFO 미구현 | −20 |
| XCTO 미구현 | −5 |
| CSP `default-src 'none'` | +10 (가산) |

- **Veracode.**
  - Security Quality Score는 0~100점이다. CWE를 결함 분류에, CVSS를 심각도 산출에 쓴다. — [Veracode Docs: Scoring methodology](https://docs.veracode.com/r/review_scoringmethodology)(검색 요약)
  - 정적·동적 스캔 결과만 점수에 반영하고 SCA 결과는 반영하지 않는다. — 같은 문서(검색 요약)
  - 비선형이라서 Severity 5 결함 1개가 Severity 1 결함 5개보다 무겁다. 같은 등급 결함이 늘수록 추가 기여는 줄어든다. — 같은 문서(검색 요약)
  - 심각도 척도는 0 Informational, 1 Very Low, 2 Low, 3 Medium, 4 High, 5 Very High다. — [Veracode: severity, exploitability](https://docs.veracode.com/r/review_severity_exploitability)(검색 요약)
  - 정확한 계수는 원문을 가져오지 못해 확인하지 못했다.
- **CWE Top 25 자체도 CVSS를 가중치로 쓴다.** 점수 공식은 빈도 × 평균 CVSS다. — [2025 Methodology](https://cwe.mitre.org/top25/archive/2025/2025_methodology.html)
- **현행 채점기 설정.** cve 감점은 `penalty_critical: 40`, `penalty_high: 25`, `penalty_medium: 10`, `penalty_low: 3`이다. 치명 감점은 T1 20~25, T2 12~15, T3 6~10이다. — 저장소 `config/scoring.yaml`

### Inferences
- **등급→감점 변환안 A: Bugcrowd형 2배 체계(추론).** Critical 1.0, High 0.5, Medium 0.25, Low 0.125, None 0의 비율로 정한다. 최대 감점을 24점으로 잡으면 Critical 24, High 12, Medium 6, Low 3, None 0이다. 장점은 공개된 산업 선례(40/20/10/5/0)를 그대로 비율화한다는 점이다.
- **변환안 B: 현행 cve 표 재사용(추론).** 40/25/10/3을 0.6배 하면 Critical 24, High 15, Medium 6, Low 2다. 저장소 안에 이미 있는 비율이라 일관성이 높다. Critical과 High의 비율이 1.6배라서 Bugcrowd(2배)보다 High를 무겁게 본다.
- **변환안 C: CVSS 점수 비례(추론).** 감점 = k × CVSS-B다. 예를 들어 k=2.5이면 9.3 → 23, 8.7 → 22, 7.1 → 18, 5.1 → 13이 된다. 등급 경계의 불연속은 없어진다. 하지만 v4의 하드닝 과대평가(6.3)를 그대로 물려받고, 0.1점 차이에 의미를 두게 된다. 그래서 **등급(밴드) 기반 A나 B가 더 견고하다**.
- **권고 조합(추론).**
  1. 등급은 위 Q2 표의 "권고 등급"을 쓴다. CVSS v4.0으로 정하되, 하드닝 항목은 v3.1과 VRT로 낮춘다.
  2. 치명 감점은 Critical과 High에만 적용한다. Critical은 24~25, High는 12~15다.
  3. Medium 이하는 치명 감점 없이 카테고리 가중치에만 반영한다.
  4. Low와 None 항목(헤더, CSP, 로깅)은 Mozilla Observatory처럼 항목별 고정 감점이 큰 체계를 따르지 않는다. Observatory는 보안 헤더만 보는 도구라서 헤더 감점이 상대적으로 클 수밖에 없다. 실제 악용 가능성을 채점하는 이 도구에는 VRT P5(0 kudos)와 CVSS 0.0 쪽이 더 맞다.
- **국내 표준과의 결합(추론).** 국내 공식(w = R + L + I)에서 R은 모두 3이라 변별력이 없다. 그래서 R을 CVSS 등급으로 바꾸는 방안을 제안한다. Critical 4, High 3, Medium 2, Low 1, None 0이고, L(법적 의무 +2)과 I(ISMS-P 명시 +1)는 그대로 둔다. 이렇게 하면 국제 심각도 차등과 국내 법적 의무가 함께 반영된다. 예시는 다음과 같다.
  - idor_profile: 3 + 2 + 1 = 6
  - security_logging: 0 + 2 + 1 = 3
  - security_headers: 1 + 0 + 0 = 1
  - sqli: 4 + 0 + 0 = 4. 별도 치명 감점이 있어서 카테고리 가중이 낮아도 무방하다.

### Gaps
- PCI DSS ASV 프로그램 가이드의 "CVSS 4.0 이상이면 불합격" 기준은 기억에 의존한 것이라 이번에 출처를 확인하지 못했다. 그래서 선례로 인용하지 않는다.
- Snyk Risk Score와 SonarQube Security Rating(가장 심각한 이슈로 A~E 등급)의 공식 수치는 조사하지 못했다.
- Veracode 점수 공식의 계수, HackerOne의 심각도별 금액·평판 점수는 공개 원문에서 확인하지 못했다.
- Bugcrowd kudos 값은 공식 문서를 직접 가져오지 않고 검색 결과 요약으로 확인했다. 블로그의 서술도 같은 값이었다.
