# Vulnerability classes AI coding agents get wrong in small web backends, and how sensitive each is to the prompt (evidence base for choosing board-app features)

Research date: 2026-10-24. This file adds to `../framework-recommendation/llm_secure_backend_benchmarks.md` and `framework_defaults_and_ai_vulns.md`. Numbers that already appear there (BaxBench per-framework tables, the Tenzai headline, Andročec 51→24) are repeated only where the ranking needs them. Everything else here is new.

Conventions:
- **[M]** = measured in the cited source. **[I]** = my inference.
- "Fail rate" = share of generated apps or samples that contain the weakness, or that lack the control.
- "Prompt sensitivity" = how far a security instruction moves that rate.
- BaxBench rates are always "share of *functionally correct* backends exploited, among those where the CWE applies". They are averaged over 11 early-2025 models and 14 frameworks unless stated otherwise.

Target-model note: the user's model, **GPT-5.6-Luna**, is the cheapest tier of OpenAI's GPT-5.6 family. Tiers, from weakest: Luna < Terra < Sol. Limited preview from 26 June 2026; priced at $1/$6 per M tokens — [CybersecurityNews](https://cybersecuritynews.com/gpt-5-6-release/amp/). One study below measures Luna directly (Deng et al., Q3).

---

## Q1. Per class: how often do LLM-generated apps fail without security prompting? Which are near-0% (no differentiation) and which near-100%?

### Takeaway
The evidence splits the classes into three bands.
- **Near-floor (≈0–15% fail; little to differentiate):** SQLi, password hashing in modern models, session-ID regeneration on login, command injection outside shell-out features.
- **Near-ceiling by default (≈80–100% fail):** CSRF, login rate limiting / brute force, security headers, log injection, and XSS wherever the framework does not auto-escape. SSRF is also near-ceiling *whenever a URL-fetch feature exists*.
- **Middle band (≈20–60% fail, high spread):** broken access control (IDOR / missing ownership checks), path traversal, upload handling, debug mode, hardcoded secrets.

Broken access control is the **#1 category in every 2026 real-app audit**, even though simple benchmark scenarios rarely trigger it.

### Cited Findings

**Large-scale 2025–2026 audits of real agent-built apps**
- **Deng, Fan, Meng, "Understanding the (In)Security of Vibe-Coded Applications"** (arXiv 2606.23130, v4 of 14 Sep 2026). Corpus: 9,041 open-source apps built with Claude Code and Lovable. Audit: 200 deployed apps, 1,186 vulnerabilities, 91.0% of apps with at least one, 65.77% Critical/High — [arXiv abs](https://arxiv.org/abs/2606.23130). [M]

  | OWASP 2025 category | Count | Share |
  |---|---|---|
  | Broken Access Control | 339 | 28.58% |
  | Injection | 199 | 16.78% |
  | Authentication Failures | 176 | 14.84% |
  | Cryptographic Failures | 112 | 9.44% |
  | Security Misconfiguration | 108 | 9.11% |
  | Supply Chain | 73 | 6.16% |
  | Logging Failures | 64 | 5.40% |
  | Insecure Design | 62 | 5.23% |
  | Exception Mishandling | 41 | 3.46% |
  | Data Integrity | 12 | 1.01% |

  Source: [arXiv HTML](https://arxiv.org/html/2606.23130)
  - Version conflict: an earlier version, as summarized by a third party, reported 10,517 repos, 1,471 vulns, 90% of repos affected, and Broken Access Control at 36.0% (present in 75.5% of repos) — [Vaughan blog on v2](https://codex.danielvaughan.com/2026/07/10/vibe-coded-insecurity-10517-apps-vulnerability-patterns-codex-cli-sandbox-hooks-defence/). Use v4 numbers. The ordering (access control first) is the same in both versions.
  - The paper gives **no per-CWE breakdown** (IDOR vs. mass assignment vs. CSRF, etc.).
- **Tenzai** (tests Dec 2025; 5 agents × 3 apps = 15 apps; agents Cursor, Claude Code, Codex, Replit, Devin; apps: shopping site, forum, file server; same stack and prompts). 69 vulnerabilities in total. Codex, Cursor and Replit about 13 each; Claude Code 16 — [@IT (ITmedia), Feb 2026](https://atmarkit.itmedia.co.jp/ait/spv/2602/09/news029.html). [M] Detail from that article:
  - **SQLi / XSS:** 0 confirmed in 15 apps (parameterized queries plus frontend framework escaping).
  - **CSRF protection absent in all 15 apps.** This resolves the item marked "unverified" in the earlier notes, but the source is Japanese press coverage, not the primary report.
  - **Security headers** (CSP, XFO, HSTS, XCTO) used by no agent.
  - **Login brute-force protection absent in 14/15 apps.** The one rate limiter (Claude Code) was bypassed by spoofing `X-Forwarded-For`.
  - **SSRF:** all 5 agents vulnerable in the link-preview feature.
  - **Authorization:** Codex's shop checked order ownership on only some routes, so other users' orders were reachable. Claude Code's file server had an *unauthenticated* delete API with no ownership check.
  - English coverage confirms the headline numbers and the "authorization was one of the most common issues" quote — [SecurityWeek](https://www.securityweek.com/vibe-coding-tested-ai-agents-nail-sqli-but-fail-miserably-on-security-controls/amp/); [InfoWorld](https://www.infoworld.com/article/4116937/output-from-vibe-coding-tools-prone-to-critical-security-flaws-study-finds-2.html)
- **Escape.tech** (published 29 Oct 2025; passive DAST over 5,600+ public apps, ~4,000 of them Lovable, plus Create.xyz, Base44 and Bolt): 2,000+ vulnerabilities, 400+ exposed secrets, 175 PII exposures. "Most vulnerabilities were exposed without authentication". Main classes: missing or misconfigured Supabase RLS, i.e. BOLA, and secrets in JS bundles. These are lower-bound numbers. No per-category counts are published — [Escape methodology](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/). [M]
- **Lovable CVE-2025-48757:** 170 of 1,645 showcase apps (~10%) had Supabase tables readable or writable with the public anon key because RLS was never enabled (303 endpoints). Lovable disputes the CVE — [Superblocks write-up](https://superblocks.com/blog/lovable-vulnerabilities); [Intruder CVE page](https://cvemon.intruder.io/cves/CVE-2025-48757). [M]
- **Wiz Research:** found apps doing the **whole authentication check client-side**, and third-party API keys and service credentials hardcoded in client JS. No rates are given — [Wiz blog](https://wiz.io/blog/common-security-risks-in-vibe-coded-apps). [M, qualitative]

**Controlled generation studies that match this stack (Flask + sqlite3, server-rendered auth)**
- **"The Illusion of Secure LLM Code"** (arXiv 2607.23710, 2026). The task is a Flask + SQLite3 app with **raw SQL, no ORM**, registration, login and dashboard — almost exactly the booth stack. Five configurations: Antigravity/Gemini 3.1 Pro, Cursor free tier, **OpenAI Codex (GPT-5.3)**, Copilot + Sonnet 4.5, Copilot + Sonnet 4.6. Basic-prompt (BP) compliance, out of 5:
  - CSRF 1/5
  - rate limiting 0/5
  - account lockout 0/5
  - inactivity timeout 0/5
  - SameSite 1/5
  - HttpOnly 3/5
  - full Secure flag 0/5
  - CSP 0/5; Referrer-Policy, XCTO and XFO each 0/5
  - strong KDF 4/5 (one used SHA-256)
  - parameterized SQL 5/5
  - session-ID regeneration on login and logout-clears-session: compliant in all 20 cells
  - Source: [arXiv HTML](https://arxiv.org/html/2607.23710). [M; cell values transcribed from a PDF table by the fetch tool, so verify before quoting exact cells]
- **Dora et al., "The Hidden Risks of LLM-Generated Web Application Code"** (arXiv 2504.20612, Apr 2025). PHP + MySQL login system. Models: GPT-4o, DeepSeek-V3, Claude 3.5 Sonnet, Gemini 2.0 Flash, Grok 3. The prompts already asked *generically* for "secure... industry-standard practices". Results:
  - Salted bcrypt/argon2 in 4/4 that hashed
  - lockout 1/5; per-IP rate limit 1/5
  - **CSRF token present 1/5**
  - session-ID regeneration 5/5; fixation protection 4/5
  - session timeout 1/5
  - cookie flags 3/5
  - parameterized SQL 5/5
  - **XSS possible in 2/5** (DeepSeek, Gemini)
  - **security headers 0/5**
  - Source: [arXiv HTML](https://arxiv.org/html/2504.20612v1). [M]
- **AppSecSanta "AI-Generated Code Security Study 2026"** (vendor, not peer-reviewed; data Feb 2026, updated 12 May 2026). Design: 87 routine prompts with no mention of security (Flask/Express/SQLite/Mongo/JWT), × 6 models (GPT-5.2, Claude Opus 4.6, Gemini 2.5 Pro, DeepSeek V3, Llama 4 Maverick, Grok 4), temperature 0, SAST plus manual triage, 154 confirmed true positives out of 926 raw findings. Results:
  - **SSRF (CWE-918) is the single most common weakness (32)**. The link-preview prompt was vulnerable in 5–6 of 6 samples for five models, and in 4 for GPT-5.2.
  - Then path traversal (30), **Flask debug on (CWE-215/489, 18)**, insecure deserialization (CWE-502, 14), NoSQL injection (10), OS command injection (6).
  - Zero findings in crypto (A04).
  - 25.7% of samples had at least one confirmed vulnerability.
  - Source: [AppSecSanta](https://appsecsanta.com/research/ai-code-security-study-2026). [M, vendor; SAST misses logic and authorization flaws by design, as the author notes]

**Benchmarks (task-level, early-2025 models)**
- **Veracode 2026 GenAI Code Security Report** (blog 28 Jul 2026; 100+ models, isolated tasks, only 4 CWEs tested). Security *pass* rates:
  - SQLi (CWE-89) 83%, i.e. **~17% fail**
  - **XSS (CWE-80) 15%, i.e. ~85% fail**
  - **log injection (CWE-117) 12%, i.e. ~88% fail**
  - crypto algorithm 87%
  - overall 56%, against 55% in 2025
  - Source: [Veracode 2026 blog](https://www.veracode.com/blog/2026-genai-code-security-report-ai-risk); Spring 2026 update has SQLi 82 / XSS 15 / log 13 — [Veracode Spring 2026](https://veracode.com/blog/spring-2026-genai-code-security). [M]
- **BaxBench scenario-level rates** (Tables 6–8, no reminder → generic → oracle; 11 early-2025 models; from [BaxBench v3](https://arxiv.org/html/2502.11844v3)). [M]

  | Scenario | CWE | none → generic → oracle |
  |---|---|---|
  | Forum | XSS (79) | .66 → .56 → .35 |
  | Forum | **SQLi (89)** | **.21** → .17 → .12 (non-trivial SQLi in the board-like scenario) |
  | Wiki | XSS | .82 → .45 → .10 |
  | ProfileCollection (user HTML profiles) | XSS | .99 → .97 → .72 |
  | ProfileCollection | CWE-400 | .49 → .48 → .36 |
  | Recipes | XSS | .85 → .79 → .43 |
  | Recipes | CWE-20 | .28 → .29 → .22 |
  | ShopOverview | XSS | .79 → .87 → .52 |
  | Login | CWE-522 | .11 → .06 → .06 |
  | Login | CWE-863 | .01 / .00 / .01 |
  | UserCreation | CWE-522 | .17 → .11 → .07 |
  | UserCreation | CWE-284 | .02 → .02 → .01 |
  | SecretStorage | CWE-284 | .51 → .48 → .37 |
  | SecretStorage | CWE-522 | 1.00 → .98 → 1.00 (plaintext secrets at rest) |
  | ShoppingCartService | CWE-20 | .10 → .06 → .07 |
  | ShoppingCartService | CWE-284 | .01 / .00 / .00 |
  | FileSearch | CWE-22 | .22 → .26 → .07 |
  | FileSearch | CWE-284 | .22 → .26 → .07 |
  | Monitor | CWE-78 | .37 → .29 → .15 |
  | ImageConverter | CWE-78 | .10 → .09 → .01 |
  | Calculator | CWE-94 | .46 → .23 → .04 |
  | Calculator | CWE-400 | .57 → .34 → .13 |
  | Logger | CWE-117 | 1.00 → .96 → .32 |

  - SQLi was .00 in Login, UserCreation, ShoppingCart, ProfileCollection, Wiki and ProductCatalog.
- **Databricks AI Red Team** (12 Aug 2025): Claude, building a multiplayer snake game component by component, chose Python `pickle` for network serialization, an RCE-grade CWE-502 flaw — [Databricks blog](https://www.databricks.com/blog/passing-security-vibe-check-dangers-vibe-coding); [heise](https://heise.de/-10521686). [M, single case]

### Master ranked table (board-style Flask + sqlite3 app; ranked by booth "differentiation value" = high default fail × high prompt sensitivity × HTTP-observable)

Default-fail column: [M] = measured, [I] = inferred. Prompt-sensitivity evidence is detailed in Q2, weak-model evidence in Q3.

| Rank | Class (CWE) | Default fail rate (source; model / era) | Prompt sensitivity | Weak vs. frontier | Booth verdict |
|---|---|---|---|---|---|
| 1 | **Login brute force / rate limit (307)** | 14/15 apps (Tenzai, Dec 2025 agents); 0/5 BP (Illusion 2026, incl. Codex GPT-5.3); 1/5 even with a generic "secure" prompt (Dora 2025) [M] | **High**: NIST-style prompt 0/5→4/5 (Illusion) [M]. A generic "secure" prompt alone is not enough (Dora) [M] | No size data. One frontier rate limiter was bypassed via XFF (Tenzai) [M] | **Top pick.** Near-100% default, fixed only by a specific instruction, cleanly observable over HTTP. |
| 2 | **CSRF (352)** | 15/15 missing (Tenzai); 4/5 missing (Illusion BP); 4/5 missing under a generic prompt (Dora) [M] | **Medium-high**: 1/5→3/5 with a NIST prompt (Illusion) [M] | No size data | **Top pick.** Must be state-changing form posts with cookie sessions. |
| 3 | **SSRF (918)**, only if a URL-fetch feature exists | 5/5 agents (Tenzai); top weakness in 6-model study, 5–6/6 vulnerable on link-preview (AppSecSanta 2026, incl. GPT-5.2, Opus 4.6) [M] | **Unknown / no measurement found.** [I] likely high for "block private IPs" wording, but DNS-rebinding and redirect-follow bypasses make full fixes rare | GPT-5.2 slightly better (4/6) than the others [M] | **Strong pick**, but a feature has to be added (link preview / avatar-by-URL). Use a canary listener probe. |
| 4 | **Broken access control / IDOR / missing ownership check (639/284/862/863)** | #1 category in real-app audits: 28.6% of 1,186 vulns (Deng v4); "one of the most common" (Tenzai; Codex partial order-ownership checks); 10% of Lovable apps (RLS) [M]. Low in simple BaxBench scenarios (284 ≤.02 except SecretStorage .51; 863 ≈0) [M] | **Low-medium**: SecretStorage 284 .51→.37 with oracle prompt (BaxBench) [M]. Deng: "production-ready" prompt cut reintroduction 25.7→11.0% overall (not class-specific) [M] | Luna reintroduces more "forgotten obligations" / "demo-oriented" defects (Q3) [M]. [I] Partial-route coverage is the typical failure mode | **Top pick**, provided the HTTP contract does **not** test cross-user denial. If it does, the loop fixes it for everyone. Multi-route ownership (edit, delete, attachment download, comment delete) gives graded partial failure. |
| 5 | **Stored / reflected XSS (79)** | Benchmarks: Veracode 85% fail; BaxBench Forum .66, Wiki .82, Profile .99 [M]. Agents with templating: 0/15 (Tenzai), Illusion n/a, Dora 2/5 [M]. In Flask, Jinja `.html` autoescape makes it a matter of whether the model uses `|safe`/`Markup`/`render_template_string` or string-built HTML [I] | **High in benchmarks**: Wiki .82→.10, Forum .66→.35, Flask .99→.44 (oracle) [M]. Generic reminder weak for non-reasoning models [M] | GPT-4o oracle .84→.48 vs o1 .96→.05 (BaxBench per-model) [M]: weak models move less | **Good pick only if a feature invites raw HTML**, e.g. markdown/rich-text post body, HTML profile bio, or a search echo outside a template. A plain Jinja form gives ~0 spread. |
| 6 | **Path traversal (22)** on file download/attachment | BaxBench Flask .33, FileSearch .22 [M]; 30 findings, second most common (AppSecSanta 2026) [M] | **High**: Flask .33→.03; FileSearch .22→.07 (oracle) [M] | — | **Good pick** if there is a download-by-filename endpoint. |
| 7 | **Unrestricted upload (434)** | BaxBench exploit almost never fires (.00) [M]; SusVibes summary lists it among frequent issues (unverified) | Unknown | — | **Medium.** [I] The useful decision surface is serving uploads inline with user-controlled Content-Type or extension (stored XSS via .html/.svg), plus size limits. |
| 8 | **Debug mode / error disclosure (489/209/215)** | Flask debug on: 18 confirmed findings across 522 samples (AppSecSanta 2026) [M] | [I] High: a single line, and models obey "disable debug" | — | **Medium.** Cheap to probe (Werkzeug console / traceback), but binary and low-variance. |
| 9 | **Hardcoded / weak secret → session forgery (798/321/1391)** | 400+ secrets in 5,600 apps (Escape 2025); client-side keys (Wiz) [M]. Deng: one agent added a hardcoded-credential login bypass to fix an auth error [M]. No Flask `SECRET_KEY` rate was measured | [I] High if the prompt says "random secret from env" | — | **Medium.** Session forgery via a guessable key is cleanly provable. The default rate is unmeasured, so it should be measured locally. |
| 10 | **Security headers / cookie flags (693/1004/1275)** | Headers 0/5 (Dora), 0/5 (Illusion BP), none in Tenzai [M]; SameSite 1/5, HttpOnly 3/5 (Illusion) [M] | **High**: SameSite 1→5/5, CSP 0→2/5, HttpOnly 3→5/5 (Illusion NIST prompt) [M] | — | **Medium.** Highly prompt-sensitive, but these are "config hygiene" rather than an exploit; weight low. |
| 11 | **Business-logic trust of client values** (price / quantity / owner id; CWE-840/602/20) | 4/5 agents did not verify prices; 3/5 let users list products at any price (Tenzai); "4/5 allowed negative orders" (SecurityWeek) [M]. BaxBench ShoppingCart CWE-20 only .10 [M] | **Low-medium**: CWE-20 Recipes .28→.22, ShoppingCart .10→.07 [M]. Tenzai: agents "depend mainly on explicit instructions" [M] | — | **Good pick in a shop/points feature**; less natural on a pure board. See Q4. |
| 12 | **Mass assignment (915)** | **No measurement found** for LLM-generated code | Unknown | — | [I] Weak lever in raw sqlite3: models write explicit column lists. It only appears if the spec has a profile-update form next to a `role` column and the model builds `UPDATE` from `request.form` keys. Must be measured locally before use. |
| 13 | **OS command injection (78)** | BaxBench Monitor .37, ImageConverter .10, Flask Table 9 .00; 6 findings (AppSecSanta) [M] | **High**: Monitor .37→.15; ImageConverter .10→.01 [M] | — | Only if a feature shells out (thumbnailing, ping). Otherwise ~0. |
| 14 | **Insecure deserialization (502)** | 14 findings (AppSecSanta 2026); Databricks pickle case [M] | [I] High (switch to JSON) | — | Low relevance. Flask session is JSON-signed by default, so only a feature that invites pickle (e.g. a "save draft/export" blob) creates it. |
| 15 | **SQLi (89)** | ≈0: Tenzai 0/15, Illusion 5/5 parameterized (raw sqlite3!), Dora 5/5, BaxBench ≤.11 per framework [M]. **Exceptions:** Veracode ~17% fail; BaxBench Forum .21 [M] | Low (already near floor): Forum .21→.12 [M] | GPT-4o .02 vs reasoning .00 (prior notes) [M] | **Low differentiation.** [I] Variance concentrates in dynamic `ORDER BY`/sort keys and `LIKE` search, where placeholders don't apply naively. Keep as a sanity/critical-penalty check. |
| 16 | **Password storage (522/916)** | Modern frontier agents ~0–20%: Illusion 1/5 used SHA-256; Dora 0/4 plaintext; BaxBench Login .11, Flask .28 [M] | **Low**: Flask .28→.28; Login .11→.06 (oracle) [M] | [I] Werkzeug `generate_password_hash` is the idiomatic Flask path, so most models pass | Low-medium. A stable floor; little participant lever. |
| 17 | **Session fixation / logout invalidation (384/613)** | Regeneration and logout-clear compliant 20/20 cells (Illusion); fixation protection 4/5 (Dora) [M] | Session timeouts: absolute 2→5/5, inactivity 0→5/5 with a NIST prompt (Illusion) [M] | — | **Low** for fixation (and Flask client-side sessions can't be "invalidated" server-side anyway [I]). Timeouts are prompt-sensitive but hard to observe in a short probe. |
| 18 | **Log injection (117)** | ~88–100% fail (Veracode 2026; BaxBench Logger 1.00) [M] | High only with an oracle prompt: Logger 1.00→.96 (generic)→.32 (oracle) [M] | — | **Exclude.** It rewards knowing the jargon, and needs log-file inspection. |
| 19 | **Resource exhaustion (400)** | BaxBench Calculator .57, Profile .49 [M] | Medium: .57→.13 [M] | — | **Exclude.** AutoBaxBuilder dropped it because exploits are "often spurious" ([AutoBaxBuilder](https://arxiv.org/html/2512.21132)). |
| 20 | **Open redirect (601)** | **No measurement found** | Unknown | — | [I] Appears only if the spec has `?next=` after login. Cheap HTTP probe. Must be measured locally. |
| 21 | **XXE (611)** | **No measurement found**; not in any benchmark reviewed | Unknown | — | **Exclude.** Python's stdlib/defusedxml-era parsers and the absence of XML in board apps make it a non-feature [I]. |
| 22 | **Race conditions / double-spend (362)** | **No measurement found**; SAST blind spot (AppSecSanta limitations) [M] | Unknown | — | [I] Hard to probe deterministically against sqlite3 + the Flask dev server. Exclude or keep exploratory. |

### Inferences
- [I] The classes with the best evidence for **"high default failure AND fixable by a specific instruction"** are rate limiting, CSRF, security headers/cookie flags, path traversal, and XSS in raw-HTML contexts. Those are the participant's real levers. Access control is the most frequent real-world failure, but its prompt sensitivity is the least measured and looks lower (BaxBench .51→.37). It differentiates on *care and coverage across routes*, not on keywords.
- [I] SQLi and password hashing should not carry differentiation weight on a Flask + sqlite3 app with a 2026 model. Three independent 2025–26 studies on this exact kind of stack found 100% parameterized SQL. If SQLi variance is wanted, it has to come from a dynamic sort/order or search feature.
- [I] BaxBench's low CWE-284/863 rates conflict with the real-app audits. BaxBench scenarios have 1–5 endpoints and one resource type. Deng's and Tenzai's apps are multi-role and multi-route. Access-control failures scale with the number of routes that need the same check. AutoBaxBench's drop in security with more endpoints, recorded in the prior notes, is consistent with this.

### Gaps
- There is no per-CWE breakdown (IDOR vs. mass assignment vs. CSRF vs. hardcoded secret) in Deng et al., Escape.tech or Tenzai's press coverage. Tenzai's original report was not retrievable (404 on the guessed URL).
- No LLM-generation measurement was found for mass assignment (CWE-915), open redirect (CWE-601), XXE (CWE-611), race conditions, or the Flask `SECRET_KEY` choice. These should be measured on pilot Luna generations before being used as features.
- The Andročec twin-prompt study does not name its agent, model, stack or per-class results in the abstract. The HTML version returned 404 — [arXiv abs](https://arxiv.org/abs/2608.20963).
- Unverified lead, not fetched this session: the Apiiro 2025 report claiming a large rise in privilege-escalation paths in AI-assisted code.

---

## Q2. Per class: does a generic or specific security instruction reliably fix it? (prompt sensitivity = the participant's lever)

### Takeaway
Specific instructions move most "missing control" classes from near 0% to 60–100% compliance (rate limiting, lockout, SameSite, timeouts). They also move CSRF and CSP partially, to 40–60%. Generic "write secure code" instructions work much less well, especially for non-reasoning or low-effort models.

Some classes barely move:
- password storage (where the framework or idiom decides)
- access control in BaxBench
- business-logic validation

Caveats on prompting:
- Prompt *style* matters. A "production-ready" framing helped about as much as a security-hardening skill. A long, "professional" technical prompt made results **worse** (+20 pp).
- Security prompts cost functionality in one-shot settings. The booth's contract loop absorbs that cost.

### Cited Findings
- **Illusion of Secure LLM Code** (Flask + sqlite3, 5 agent configurations incl. Codex GPT-5.3). Compliance, basic prompt → NIST-based single-shot prompt → iterative reprompting, out of 5 — [arXiv 2607.23710](https://arxiv.org/html/2607.23710) [M; transcription caveat]:

  | Control | Basic | NIST | Reprompt |
  |---|---|---|---|
  | Rate limiting | 0 | 4 | 4 |
  | Account lockout | 0 | 4 | 5 |
  | CSRF | 1 | 3 | 3 |
  | SameSite | 1 | 5 | 5 |
  | HttpOnly | 3 | 5 | 5 |
  | Full Secure flag | 0 | 1 | 3 |
  | CSP | 0 | 2 | 2 |
  | XFO / XCTO / Referrer-Policy | 0 | 2 | 2 |
  | Inactivity timeout | 0 | 4 | 5 |
  | Strong KDF | 4 | 5 | 5 |
  | Explicit work factor | 0 | 1 | 1 |
  | Parameterized SQL | 5 | 5 | 5 |

- **Dora et al. 2025:** with a *generic* "secure, industry-standard" prompt, rate limiting was still 1/5, CSRF 1/5 and headers 0/5. Generic wording does not trigger specific controls — [arXiv 2504.20612](https://arxiv.org/html/2504.20612v1). [M]
- **Tenzai lesson 1:** agents "rarely add security measures unprompted"; security requirements must be explicit — [@IT](https://atmarkit.itmedia.co.jp/ait/spv/2602/09/news029.html). [M, qualitative]
- **Deng et al. RQ.4** (70 replayed vulnerabilities × 8 configurations × 3 repeats = 1,680 runs; share of runs that *reintroduced* the vulnerability; baseline = default harness + GPT-5.6-Terra + short non-expert prompt) — [arXiv HTML](https://arxiv.org/html/2606.23130) [M]:

  | Configuration | Reintroduction rate |
  |---|---|
  | Baseline | 25.7% |
  | **"Production-ready" prompt** | **11.0%** |
  | Security-hardening skill (harness) | 11.9% |
  | Polished prompt | 22.9% |
  | Self-check prompt | 23.8% |
  | **"Professional" detailed technical prompt** | **45.7%** (worse; authors: the agent followed the detailed spec more literally) |
  | Weaker model, Luna | 39.5% |
  | Stronger model, Sol | 26.2% |

  - In 20.7% of triggered runs (90/434), the agent *recognized* the risk and shipped the insecure code anyway.
  - No configuration eliminated all target vulnerabilities.
- **BaxBench, per class, none → generic → oracle** (early-2025 models) — [BaxBench v3](https://arxiv.org/html/2502.11844v3) [M]:
  - XSS (Wiki): .82 → .45 → .10. Very sensitive.
  - XSS (Forum): .66 → .56 → .35. XSS (Profile): .99 → .97 → .72. XSS (Flask, all scenarios): .99 → .90 → .44.
  - Path traversal (Flask): .33 → .03 (oracle). Command injection (Monitor): .37 → .15. Code injection (Calculator): .46 → .04.
  - Log injection (Logger): 1.00 → .96 → .32. This needs the specific instruction.
  - CWE-522 (Flask): .28 → .28. Insensitive.
  - CWE-284 (SecretStorage): .51 → .48 → .37. Weakly sensitive.
  - CWE-20 (Recipes .28 → .22; ShoppingCart .10 → .07). Weakly sensitive.
  - Reasoning models (o1, o3-mini, R1) improved on the *generic* reminder; non-reasoning models did not. GPT-5's pass@1 fell 70.7 → 50.5 under the oracle prompt (prior notes).
- **SoK on AI secure code generation** (arXiv 2606.25195, 2026). A generic security-aware prompt on **GPT-5.1-Codex-Mini** raised secure@pass1 on CWEval from 71.3 to 87.8 and on BaxBench from 65.0 to 71.1. For Qwen2.5-14B the same prompt gave CWEval 59.8 → 63.0 and BaxBench 30.0 → 41.7. In a separate test on GPT-5.1-Codex-Mini, 20 CWEval tasks flipped from fail to pass and 6 flipped the other way (p = 0.009) — [arXiv HTML](https://arxiv.org/html/2606.25195). [M]
- **Backslash Security** (vendor, Apr 2025; 7 models, 3 prompt tiers, 10 CWEs; full method not published):
  - GPT-4o scored 1/10 secure under naive prompts, and was still vulnerable to 8/10 CWEs when asked to "generate secure code".
  - GPT-4.1 scored 1.5/10 under naive prompts.
  - Claude 3.7 Sonnet scored 6/10 naive and 10/10 with security-focused prompts.
  - Source: [Backslash press release](https://www.backslash.security/press-releases/backslash-security-reveals-in-new-research-that-gpt-4-1-other-popular-llms-generate-insecure-code-unless-explicitly-prompted); [BetaNews](https://betanews.com/2025/04/24/popular-llms-produce-insecure-code-by-default/). [M, vendor, low transparency]
- **Databricks:** self-reflection, language-specific and generic security prompts "significantly reduce" insecure code generation (no per-class numbers in what was retrieved) — [Databricks](https://www.databricks.com/blog/passing-security-vibe-check-dangers-vibe-coding). [M, qualitative]
- **Contrary evidence for agents on real repos:** SusVibes found that adding vulnerability hints to feature requests did not mitigate the issues — [SusVibes](https://arxiv.org/abs/2512.03262) (prior notes). The Endor Labs extension reports agents ignoring explicit instructions, for example by mining git history — [Endor Labs](https://www.endorlabs.com/learn/is-ai-coding-safe-introducing-the-agent-security-league). [M]

### Inferences
- [I] **Lever ranking for a ≤1000-char participant prompt**, from most to least reliable:
  1. Named missing controls: rate limit/lockout, CSRF tokens, cookie flags, headers, debug off, random secret from env.
  2. Classic injection-style input handling: path traversal, XSS in raw-HTML contexts, command injection.
  3. Authorization coverage: "check ownership on every edit/delete/download route".
  4. Business-logic validation.

  Items 1–2 are keyword-triggered; 3–4 require the model to apply a rule consistently across routes. Weak models are measurably worse at that (Q3).
- [I] **Scoring-design caution from Deng:** a long, detailed, "professional" prompt raised reintroduction by 20 pp. Participants who paste huge spec-like prompts may score *worse* than those who write a short "production-ready, secure-by-default" framing plus a few named controls. That is a legitimate and interesting differentiator, but it should be expected and explained at the booth.
- [I] Because the harness loops until functional tests pass, the one-shot functionality penalty of security prompts (BaxBench, GPT-5 −20 pp pass@1) is absorbed. But a repair loop can **remove** security to make tests pass: Deng's "function-fix side effects" defect class accounts for 100 of 1,186 vulnerabilities. Contract tests must never fail because of a correct security control, for example a test POST without a CSRF token or rapid repeated logins tripping a rate limit. Otherwise the loop will strip the participant's controls. This matches the "never penalize a grader/contract-imposed constraint" rule.

### Gaps
- No measurement was found of prompt sensitivity for SSRF, IDOR (beyond BaxBench SecretStorage), mass assignment, open redirect, or upload handling.
- No study varies *prompt length or wording style* per CWE apart from Deng's aggregate eight-configuration replay.

---

## Q3. Do smaller, older or faster models (GPT-4o-mini, gpt-5-mini/nano, Luna-class) differ systematically from frontier models in which classes they fail?

### Takeaway
Yes, in overall rate. Model size or tier is a weak predictor in Veracode's large isolated-task sample, but a strong one in multi-endpoint backend benchmarks, and Deng et al. measured **GPT-5.6-Luna** directly:
- Luna reintroduced vulnerabilities in 39.5% of runs, against 25.7% for Terra and 26.2% for Sol.
- Luna's excess failures concentrate in "demo-oriented design", "forgotten obligations" and "hidden security rules".

These are exactly the classes behind missing controls and partial authorization coverage. Per-CWE small-vs-frontier tables do not exist. Whether a generic reminder works depends on reasoning: non-reasoning models ignore generic reminders, and Luna at low effort probably behaves closer to them [I].

### Cited Findings
- **Deng et al. RQ.4:**
  - Luna 83/210 runs reintroduced the vulnerability (39.5%), against Terra 54/210 (25.7%).
  - Going from Luna to Terra cut reintroduction by 13.8 pp. Going from Terra to Sol made it 0.5 pp worse.
  - Luna's per-failure-mode reintroduction rates: insecure instructions 66.7% (8/12, small n), demo-oriented design 42.9% (18/42), forgotten obligations 42.9% (9/21), hidden security rules 40.9% (27/66).
  - The reasoning-effort setting is not stated.
  - Source: [arXiv HTML](https://arxiv.org/html/2606.23130). [M]
- **Veracode 2026:** large models (>100B) averaged 53%, medium 51%, small 51%; reasoning 56% vs non-reasoning 51%. GPT-5.5 was best at 68%; more than half the models scored 50–53% — [Veracode](https://www.veracode.com/blog/2026-genai-code-security-report-ai-risk). [M] Size barely matters on Veracode's 4 single-function CWEs.
- **BaxBench leaderboard** (no reminder; sec_pass@1, insecure-of-correct):
  - GPT-4.1 40.8% (~28%) vs **GPT-4.1 Mini 28.4% (~41%)**
  - **o3-mini** 34.4% vs o3 46.4%
  - GPT-5 54.3% (~23%)
  - Source: [baxbench.com data](https://baxbench.com/static/data/leaderboard_data_none.json) (prior notes). [M]
- **AutoBaxBench scaling** (Python-FastAPI sec_pass@1, with pass@1 in parentheses):

  | Model | sec_pass@1 (pass@1) |
  |---|---|
  | Qwen2.5 7B | 2% (5%) |
  | Qwen2.5 72B | 5% (18%) |
  | Llama3.3 70B | 5% (18%) |
  | Codestral | 10% (31%) |
  | GPT-4o | 16% (41%) |
  | Gemini 2.5 Pro | 31% (55%) |
  | Sonnet 3.7 | 34% (68%) |
  | Gemini 3 Pro | 43% (74%) |
  | Sonnet 4.5 | 44% (81%) |

  Source: [AutoBaxBuilder](https://arxiv.org/html/2512.21132). [M] Insecure-of-correct stays around 45–75% across sizes. Weaker models fail functionality more, and security roughly in proportion.
- **BaxBench per-model XSS under the oracle prompt:** GPT-4o .84 → .48, while o1 .96 → .05, Claude-3.5 .70 → .01, R1 .83 → .15 — [BaxBench v3](https://arxiv.org/html/2502.11844v3) (prior notes). [M] The weaker non-reasoning model follows the specific instruction much less completely.
- **BaxBench §4:** "o1, o3-mini and R1 show considerable improvement already on just the generic security reminder, while the non-reasoning models do not" (prior notes). [M]
- **GPT-5.1-Codex-Mini** (a "mini" Codex model) *did* respond to a generic security prompt: CWEval secure@pass1 71.3 → 87.8, BaxBench 65.0 → 71.1 — [SoK 2606.25195](https://arxiv.org/html/2606.25195). [M]
- **CWEval leaderboard** (func-sec@10): GPT-4o mini 60.28% vs GPT-4o 65.33% — [alphaXiv CWEval](https://alphaxiv.org/benchmarks/columbia-university/cweval) (aggregator; not re-verified against the paper). [M, secondary]
- **Open models + secure prompt** (pass@10 F+S, from the same search; paper not opened): Gemma3-4B 30.25 → 30.25 (no gain) vs Gemma3-12B 39.50 → 48.74; Qwen3-8B 43.70 → 57.14, Qwen3-14B 52.94 → 68.91 — [via search summary of arXiv 2606.16244 / related](https://arxiv.org/pdf/2606.16244). [M, secondary; verify] The smallest model ignored the security prompt entirely.
- **Agent harness on real repos:** Codex + GPT-5.4 had the highest SecPass on the Endor Agent Security League (17.3% secure, 62.6% functional, Mar 2026), ahead of Cursor + Opus 4.6 (7.8% / 84.4%) — [Endor Labs](https://www.endorlabs.com/learn/is-ai-coding-safe-introducing-the-agent-security-league). [M] The OpenAI Codex lineage tends to be relatively security-conservative per correct solution; the BaxBench GPT-5 insecure-of-correct of ~23% agrees.
- **AppSecSanta 2026:** GPT-5.2 had the lowest vulnerable-sample rate, 19.5% (11.6% in Python), against 29.9% for Opus 4.6, DeepSeek V3 and Llama 4 Maverick — [AppSecSanta](https://appsecsanta.com/research/ai-code-security-study-2026). [M]
- **Semgrep's July 2026 GPT-5.6 evaluation covers vulnerability *detection*, not generation.** Luna had about 6× lower cost per true positive with a marginal F1 drop. It is not evidence about Luna's generated-code security — [Semgrep](https://semgrep.dev/blog/2026/gpt-5-6-benchmarks-ai-code-security/). [M]

### Inferences
- [I] For Luna at reasoning effort *low*, expect behaviour between "non-reasoning" and "mini reasoning". Generic "make it secure" prompts should give modest gains. Named controls should give larger gains. Partial application should be common, e.g. CSRF on some forms only, or an ownership check on edit but not delete. That last pattern is Deng's "forgotten obligations" and "incomplete change propagation", where Luna was measurably worse.
- [I] This argues for **multi-route features with the same security obligation**: edit, delete, attachment download, comment delete and admin action all need the authz check; every POST form needs CSRF. A partial fix then scores partially, which creates a gradient between participants instead of a binary.
- [I] Weak models raise the default failure floor. So "near-0% for frontier" classes may be non-zero for Luna, in particular SQLi in search/sort, XSS via `|safe`, and password hashing. These should be **measured on ~10 pilot Luna generations with a neutral prompt** before features are finalised. No published Luna per-CWE data exists.

### Gaps
- No per-CWE table compares small and frontier models on the same backend tasks. BaxBench's per-model Tables 12–14 could not be extracted (truncated); prior notes only have per-model XSS.
- The reasoning-effort setting is not reported in Deng et al., and no study varies `reasoning_effort` (low/medium/high) for security.
- GPT-5-mini/nano: no backend-security benchmark entries were found.

---

## Q4. Which business-logic flaws (not classic CWEs) do AI agents commonly produce in CRUD apps?

### Takeaway
There is solid evidence for three patterns:
1. **Trusting client-supplied economic values.** Price, total and product price at creation: 4 of 5 agents in Tenzai; negative orders reported for 4/5.
2. **Inconsistent ownership or role checks across routes.** Some routes checked, others not, or delete is unauthenticated: Tenzai, Deng (broken access control is the #1 category), Lovable/Escape (BOLA via missing RLS).
3. **"Demo-oriented" shortcuts.** Hardcoded bypass credentials, client-side auth, debug left on: Deng, Wiz.

Agents "lack common sense" here and "depend mainly on explicit instructions". The flaws are moderately prompt-sensitive, but only when the participant names the specific rule.

### Cited Findings
- **Tenzai (Dec 2025):**
  - Four agents (Claude Code, Cursor, Devin, Replit) did not verify prices, so items could be bought at an arbitrary total.
  - Cursor, Devin and Replit let users register products at any price; Replit's listing API did no input validation.
  - Codex checked order ownership on only some routes.
  - Claude Code's file server allowed unauthenticated delete with no ownership check.
  - Source: [@IT](https://atmarkit.itmedia.co.jp/ait/spv/2602/09/news029.html). [M]
  - SecurityWeek's coverage: "4/5 allowed negative orders" (prior notes) — [SecurityWeek](https://www.securityweek.com/vibe-coding-tested-ai-agents-nail-sqli-but-fail-miserably-on-security-controls/amp/). The @IT article does not mention negative quantities, so the two press accounts emphasize different examples of the same price/quantity-validation failure.
  - Agents lack business-logic "common sense" and depend on explicit instructions — [SecurityWeek](https://www.securityweek.com/vibe-coding-tested-ai-agents-nail-sqli-but-fail-miserably-on-security-controls/amp/). [M]
- **Deng et al. root causes** (of 1,186 vulnerabilities):
  - hidden security rules (658): rules the developer never stated
  - demo-oriented design (174)
  - incomplete change propagation (110): a fix applied in one place, not everywhere
  - function-fix side effects (100): security removed or weakened to make something work
  - user-dependent security (72)
  - forgotten obligations (50)
  - hallucination (13); insecure instructions (9)
  - Concrete examples: a healthcare app with broken access control exposing customer data, and **a login-bypass route with hardcoded credentials added to work around an auth error**.
  - Source: [arXiv HTML](https://arxiv.org/html/2606.23130). [M]
- **BaxBench ShoppingCartService CWE-20** (e.g. invalid quantities): only .10 → .06 → .07; Recipes CWE-20 .28 → .22 — [BaxBench v3](https://arxiv.org/html/2502.11844v3). [M] With a one-resource spec that names the fields, input-validation failures are moderate and barely prompt-sensitive.
- **Wiz:** authentication performed entirely client-side, and secrets in client JS — [Wiz](https://wiz.io/blog/common-security-risks-in-vibe-coded-apps). [M]
- **Escape / Lovable:** most exposed data was reachable without authentication, through missing row-level authorization — [Escape](https://escape.tech/blog/methodology-how-we-discovered-vulnerabilities-apps-built-with-vibe-coding/); [Superblocks](https://superblocks.com/blog/lovable-vulnerabilities). [M]

### Inferences
- [I] Business-logic flaws suited to a **board** app, each a decision the contract can leave open and the grader can probe over HTTP:
  - (a) edit/delete of another user's post or comment, on *each* route separately
  - (b) a hidden or private post or attachment readable by id
  - (c) a `role`/`is_admin` or `author_id` field accepted from the form on profile update or post create (mass assignment / client-supplied owner id)
  - (d) admin actions callable by normal users (function-level authz)
  - (e) for a points/like/vote feature: negative or repeated votes and self-voting (client-trusted quantities)
  - (f) a pagination `limit` without a cap (resource use)

  Items (a), (b) and (d) are the best evidenced (Tenzai, Deng, Escape). Item (c) is plausible but unmeasured. Item (e) maps onto Tenzai's price and quantity finding.
- [I] For the contract loop: the contract must specify *that* an edit endpoint exists and what a successful owner edit returns. It must **not** specify the response to a non-owner. Otherwise every app passes by construction and there is no participant variance. This is the same rule as for CSRF and rate limiting in Q2.

### Gaps
- No quantified per-agent rate was found for mass assignment, self-voting/double-voting, or race-condition double-spend in AI-generated CRUD apps.
- The Tenzai primary report (exact counts per flaw type per agent) was not retrieved; only press coverage was available.
