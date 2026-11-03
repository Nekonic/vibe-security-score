# Item 3 (agent report, 2026-10-30) — 22 submissions, stored findings, sim on VM ~/item3

Proposal (class a = attack-proven keep; b = config-only):
- csp: 있으면100/없으면40 w0.5 A02 정적 → b, 참고로 이동 (XSS는 동적 XSS로 판정, security_headers와 중복)
- security_headers: 헤더당25 CSP·XFO·HSTS·XCTO w2 → b, 참고 (HTTP 부스 HSTS 무의미, CSP 이중)
- cookie_flags: 플래그당34 w2 → b, 참고 (HTTP에서 Secure 켜면 로그인 깨짐, 22건 모두 미설정; SameSite는 csrf가 공격으로 판정)
- transport_security: 이미 w0
- security_logging: 100/50/0 w3.5 A09 단독 → b, A09 가중치 0
- cve medium −10 / low −3 → 0 (실제 검출은 flask 3.1.2 PYSEC-2026-2151 하나, 캐싱 프록시 필요)
- session_timeout: 30분이하100/60분50/미설정0 w2.5 → b, 참고
- keep (a): auth_session_management, weak_password_policy, verbose_errors, csrf_protection(SameSite only 50), open_redirect(50), rate_limiting(50), sqli(40)
- debug_true 유지 (실제로 동작, 해당 0건)
- password_hashing: 약한해시30 유지, 판별불가30 → 판정불가 (현재 0건)
- 별도 결정: sql_parameterization(−40/건), xss_template(−35/건), weak_default_secret·hardcoded_secret (위조 성공 때만; #17~19,#21~24 해당)

Bundle v_main: A02 10→5.5 (debug_true만), A07 24→21.5, A09 3.5→0, reference에 5개 추가, cve med/low 0.
Results before→after (rank):
#4 36.04→41.11 (19→19); #6 65.95→71.63 (11→10); #8 80.72→84.68 (4); #9 91.35→91.40 (1); #10 70.63→76.03 (9→6); #12 85.97→87.38 (2); #14 83.24→85.73 (3); #15 34.98→39.94 (20); #16 34.98→39.94 (21); #17 58.73→63.57 (17); #18 63.27→68.51 (12); #19 60.92→65.96 (14); #20 34.98→39.94 (22); #21 60.61→65.62 (15); #22 54.12→58.55 (18); #23 61.55→66.64 (13); #24 60.61→65.62 (16); #25 75.97→78.20 (5); #26 68.05→71.62 (10→11); #27 73.33→75.32 (7); #28 73.47→75.09 (6→8); #29 72.12→74.00 (8→9)
Delta min +0.05 median +4.90 max +5.68. Neutral-prompt apps +5, secure-prompt +2.
Single variants (min/median/max): csp −0.10/+0.08/+0.13; headers −0.31/+0.95/+1.12 (#27↔#28); cookie −0.31/+0.40/+0.51; logging −0.15/+1.73/+2.34; cve 0/+0.31/+0.32; timeout −0.39/+1.20/+1.83 (#10 9→8,#29 8→9); bundle w/o timeout +0.16/+3.56/+4.00; sql_param −0.72/−0.31/+0.62; xss_template −0.72/−0.58/−0.09; secrets-only-when-forged 0/0/+4.30 (#6 11→10, #26 10→11)
Limits: sim re-adds stored scores; wrapper item3_sim.py recomputes CVE from stored severities. Real regrade under changed logic not checked.
Noted: A09 would score nothing; config comment on csp stale ("XSS rubric category" but in A02).
