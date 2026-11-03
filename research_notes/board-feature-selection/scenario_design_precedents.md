# Scenario/feature design precedents: is a board the right base for an AI-generated-app security grader?

Scope: how benchmarks (BaxBench, AutoBaxBench), training apps (Juice Shop, crAPI, VAmPI, PortSwigger), AI-coding-agent studies (Tenzai, Veracode), and CTF/education work pick scenarios that force security decisions. Current as of 2026-10-24. Grounding: the current spec in `config/default_prompt.md` (board: signup/login with phone, posts with optional image + `link_url` preview fetch, comments, search, profile + avatar via file or `avatar_url`, admin user list/role/delete). Note that commit `1530d6f` ("객체·댓글 권한 프로브 제거") removed the object/comment authorization probes.

## Q1. Which BaxBench scenarios/features showed the largest security spread and prompt sensitivity?

### Takeaway
The spread between "no security instruction" and "told what to defend" is largest where the risk is invisible in the functional spec: log injection (Logger), stored XSS (Recipes, ProfileCollection), path traversal (RegexSearch, Compiler, SongDownloader) and code eval (Calculator). Plaintext secret storage (SecretStorage, CWE-522) stayed near 100% even with oracle hints, so prompts did not fix it. Classic SQLi is almost never present in modern-model output. Pure CRUD scenarios (ClickCount, Login, Unsubscribe) show almost no CWE signal.

### Cited Findings
- BaxBench has 28 scenarios × 14 frameworks = 392 tasks, with 54 endpoints in total (1–5 per scenario, about 2 on average) — [BaxBench v3](https://arxiv.org/html/2502.11844v3)
- Scenario selection criteria — [BaxBench v3](https://arxiv.org/html/2502.11844v3):
  - common in real-world development
  - complexity beyond the function level
  - potential security vulnerabilities
  - implementable correctly and securely in existing frameworks
- Scenarios and the CWEs each can exhibit (BaxBench Table 4) — [BaxBench v3](https://arxiv.org/html/2502.11844v3):

  | Scenario | Endpoints | CWEs |
  |---|---|---|
  | Forum | 1 | 79/89/703 |
  | Wiki | 3 | 79/89/703 |
  | Recipes | 5 | 20/79/703 |
  | ProfileCollection | 3 | 79/89/400/703 |
  | ImageTransfer | 2 | 22/79/284/434/703 |
  | SecretStorage | 4 | 89/284/522/703/863 |
  | ShopOverview | 4 | 79/522/703/863 |
  | ShoppingCartService | 3 | 20/89/284/703 |
  | CreditCardService | 2 | 89/284/703 |
  | Calculator | 1 | 94/400/703 |
  | Logger | 2 | 117/703 |
  | Unsubscribe | 1 | 703/863 |

- Per-scenario CWE occurrence ratio, as no prompt / generic reminder / oracle prompt (BaxBench Tables 6–8; ratio = functionally correct backends that have the CWE ÷ those that could have it) — [BaxBench v3](https://arxiv.org/html/2502.11844v3):

  | Scenario | CWE | No prompt | Generic | Oracle |
  |---|---|---|---|---|
  | Logger | 117 | 1.00 | 0.96 | 0.32 |
  | ProfileCollection | 79 | 0.99 | 0.97 | 0.72 |
  | Recipes | 79 | 0.85 | 0.79 | 0.43 |
  | RegexSearch | 22 | 0.84 | 0.71 | 0.20 |
  | RegexSearch | 400 | 0.99 | 0.96 | 0.72 |
  | Compiler | 22 | 0.62 | 0.49 | 0.12 |
  | SongDownloader | 22 | 0.73 | 0.53 | 0.08 |
  | Calculator | 94 | 0.46 | 0.23 | 0.04 |
  | ZipToTxt | 400 | 0.83 | 0.81 | 0.78 |
  | SecretStorage | 522 | 1.00 | 0.98 | 1.00 |

- ClickCount, Login, PDFCat and Unsubscribe are near 0.00 on most CWEs under all three conditions — [BaxBench v3](https://arxiv.org/html/2502.11844v3)
- Paper text: for scenarios "e.g., Logger or Forum, security reminders have a decisive impact". Models "primarily fail" to consider security unless told — [BaxBench v3](https://arxiv.org/html/2502.11844v3)
- Calculator has the highest security token overhead (+15.1%, vs ~5% on average). The secure solution is a safe parser instead of `eval` — [BaxBench v3](https://arxiv.org/html/2502.11844v3)
- AutoBaxBench Table 3 (FastAPI/Fastify/Gin):
  - CWE-89 appears in only 0–1% of correct solutions.
  - CWE-20 appears in 34–48%.
  - CWE-79 appears in 12–14%, though the paper's text calls XSS "dominant", which is internally inconsistent.
  - Source: [AutoBaxBuilder](https://arxiv.org/html/2512.21132)
- AutoBaxBuilder's generation prompt "encourages the proposal of backends that expose a clear attack surface if implemented carelessly". It also checks novelty against existing scenario names — [AutoBaxBuilder](https://arxiv.org/html/2512.21132)
- AutoBaxBuilder excludes CWE-400 because its exploits are "often spurious". Its exploits are accepted contrastively (they must flag a vulnerable reference solution and pass a patched one) — [AutoBaxBuilder](https://arxiv.org/html/2512.21132)
- AutoBaxBench difficulty by subset — [AutoBaxBuilder](https://arxiv.org/html/2512.21132):

  | Subset | Avg. endpoints | Avg. CWEs | Best sec_pass@1 |
  |---|---|---|---|
  | Easy | 1.0 | 1.6 | 36% |
  | Medium | 3.0 | 2.7 | 40% |
  | Hard | 4.7 | 3.5 | 25% |

  More endpoints generally means a lower secure-and-correct rate, but the trend is not monotonic.

### Inferences
- **The "Forum" scenario is a weak differentiator on its own.** BaxBench's Forum is 1 endpoint with XSS/SQLi/crash only. SQLi is now near zero in modern-model output. XSS in server-rendered Jinja2 is suppressed by autoescape, unless the model builds HTML strings or uses `|safe`/`Markup`.
- **Most of the signal in the current board app comes from the non-board extras:** the link preview (SSRF), avatar upload and `avatar_url` (upload/SSRF), private phone (data exposure), and admin role (BFLA). The posts/comments core contributes little.
- **The most prompt-sensitive items share one property: the functional spec is silent about the danger** (log lines, rendered HTML, file paths, expression evaluation). A participant's prompt can name the danger, and the model can then comply. This is exactly the participant-fixable property the booth needs.
- **SecretStorage/CWE-522 should not be scored as a prompt-fixable item.** Prompts did not move it even with oracle hints. If kept, it should be gated on a framework hasher being available (werkzeug `generate_password_hash` is available in Flask). The memory note that the password policy was removed is consistent with this.

### Gaps
- Per-scenario pass@1/sec_pass@1 bar values (Fig. 6, App. D.3) were not extractable from the HTML. I found no per-scenario × per-framework (Flask-only) cross-tab.
- I did not retrieve AutoBaxBench's generated scenario list with CWEs, apart from mentions of SVGBadgeForge, FrameExtract, FileSearch, ZipToTxt and Compiler.

## Q2. Which feature set covers the most OWASP Top 10 2025 and API Top 10 2023 categories with the fewest endpoints?

### Takeaway
About 8 features cover nearly all of both lists:
- multi-user private objects, for BOLA
- a role-gated admin function, for BFLA
- a user-editable profile with server-owned fields, for BOPLA/mass assignment
- an outbound URL fetch, for SSRF
- a file upload, for upload handling and path traversal
- a rendered user-content view, for XSS
- a value-bearing business action (money, quantity or quota), for business logic and insecure design
- login/session, for authentication

Supply chain (A03) and logging (A09) are poorly observable over HTTP whatever the domain.

### Cited Findings
- OWASP Top 10 2025 categories — [OWASP Top 10 2025](https://top10.owasp.org/2025):
  - A01 Broken Access Control
  - A02 Security Misconfiguration
  - A03 Software Supply Chain Failures
  - A04 Cryptographic Failures
  - A05 Injection
  - A06 Insecure Design
  - A07 Authentication Failures
  - A08 Software or Data Integrity Failures
  - A09 Security Logging and Alerting Failures
  - A10 Mishandling of Exceptional Conditions
- OWASP API Security Top 10 2023 — [OWASP API Top 10 2023](https://api-security.owasp.org/editions/2023/en/0x11-t10):
  - API1 BOLA
  - API2 Broken Authentication
  - API3 Broken Object Property Level Authorization
  - API4 Unrestricted Resource Consumption
  - API5 BFLA
  - API6 Unrestricted Access to Sensitive Business Flows
  - API7 SSRF
  - API8 Security Misconfiguration
  - API9 Improper Inventory Management (e.g., exposed debug endpoints)
  - API10 Unsafe Consumption of APIs
- VAmPI covers 9 vulnerability classes with ~14 method+path operations in a "users + books with a secret" domain — [VAmPI](https://github.com/erev0s/VAmPI):
  - SQLi
  - unauthorized password change
  - BOLA
  - mass assignment
  - excessive data exposure via a debug endpoint
  - user/password enumeration
  - RegexDoS
  - no rate limiting
  - JWT weak-key bypass
- crAPI's challenge list maps vulnerabilities onto domain objects (the feature mapping is partly the fetch model's inference from the challenge titles) — [crAPI challenges](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md):
  - another user's vehicle location and mechanic reports (BOLA)
  - resetting another user's password
  - an endpoint leaking other users' data
  - an internal video property leak or update (BOPLA/mass assignment)
  - deleting another user's video
  - "get an item for free" and "increase your balance by $1,000" (business logic/refund)
  - coupon abuse
  - making the server call an external site (SSRF)
  - an endpoint without auth
  - JWT forgery
  - chatbot prompt injection

### Inferences
Each recommended feature, with the observable HTTP probe and the categories it covers:

| Feature | Observable HTTP probe | Categories |
|---|---|---|
| Private per-user object (note, file, order, secret) | User B GETs, PUTs or DELETEs user A's object id | A01, API1 |
| Admin-only function | Normal user calls `/admin/...` | A01, API5 |
| Self-profile update with a server-owned field (`role`, `balance`, `is_admin`) | Send the extra field and check whether it persists | A01/A06, API3 |
| Public listing that serializes user objects | Look for a private field (phone/email) in HTML/JSON | A01/A04, API3 |
| Outbound URL fetch (preview/import/webhook) | Callback canary or internal metadata IP | A01 (SSRF is folded into A01 in 2025; this is inference, since the fetched page did not state the merge), API7 |
| File upload served back | `.html`/`.svg` served as `text/html` (stored XSS), or path traversal in the filename | A05/A06 |
| Render of user content and search reflection | Unescaped payload returned as `text/html` | A05 |
| Value action (transfer, order, redeem coupon) | Negative or overflowing quantity, replay, or a concurrent double-spend | A06, API6 |
| Login/session | Weak or forgeable secret key, no session rotation, enumeration | A07/A02 |
| Malformed input | 500 with traceback (debug) | A10/A02 |

- The current board already covers about 7 of these 10. **It lacks a private-object BOLA surface:** posts are public, and the edit/delete owner check is spec-imposed. **It also lacks a value/business-flow action** (A06/API6).

### Gaps
- I found no published "minimum endpoint set" analysis. The mapping above is inference.
- I did not fetch the A01:2025 page text, so the claim that SSRF is merged into A01 is unverified.

## Q3. Do domain features (ownership, roles, money/quantities, files, outbound URLs) differentiate better than generic CRUD?

### Takeaway
Yes, and the evidence is strong for current coding agents. Agents avoid well-known pattern bugs (SQLi/XSS) but consistently miss authorization, business logic, SSRF and "security controls" whenever the spec does not mention them. Generic CRUD mainly exercises the bug classes models already avoid.

### Cited Findings
- Tenzai (Dec 2025) had Cursor, Claude Code, OpenAI Codex, Replit and Devin each build the same 3 apps from identical prompts. Findings — [SecurityWeek](https://www.securityweek.com/vibe-coding-tested-ai-agents-nail-sqli-but-fail-miserably-on-security-controls/):
  - 69 vulnerabilities in total.
  - Zero exploitable SQLi or XSS.
  - "improper authorization when accessing APIs" was among the most common issues.
  - All 5 agents introduced SSRF on the "SSRF pitfall".
  - When the prompt did not specify it, 4 of 5 allowed negative order quantities and 3 of 5 allowed negative product prices.
  - Agents "failed miserably" on security controls, and in most cases "didn't even try".
  - Tenzai's summary: agents are good where "good coding practices are well established" and bad where rules are unclear (complex authorization, business logic).
- Secondary reports on the same study:
  - Negative refund quantity yielded money ("reverse transaction"), and Codex was the exception on the negative-quantity payment — [Vibe Graveyard summary](https://vibegraveyard.ai/story/tenzai-ai-coding-tools-vulnerability-study/); [@IT (Japanese)](https://atmarkit.itmedia.co.jp/ait/spv/2602/09/news029.html)
  - In the Codex app, a seller could view other customers' spending breakdowns, which is a BOLA/BOPLA leak — [@IT (Japanese)](https://atmarkit.itmedia.co.jp/ait/spv/2602/09/news029.html)
  - These reports conflict slightly on the total (69 vs 70) — [AppSec Day Israel 2026 listing](https://appsecdayisrael2026.sched.com/event/2WQZA)
- Veracode 2025 GenAI Code Security Report (80 tasks, 100+ LLMs):
  - Insecure code in 45% of cases.
  - XSS (CWE-80) failed 86% and log injection (CWE-117) failed 88%.
  - Model size did not significantly help.
  - Source: [Veracode press release](https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/)
- The Nov 2025 Veracode update still shows XSS pass rates under 14% and log-injection pass rates near 12%. GPT-5 Mini had the highest overall pass rate at 72% — [Veracode Nov 2025](https://www.veracode.com/press-release/veracode-research-reveals-openais-gpt-5-models-lead-the-way-in-secure-code-while-wider-industry-progress-stalls/)
- **Note the conflict:** Veracode (function-level tasks, SAST-judged) reports XSS failing at ~86%, while Tenzai (full apps, pentest-judged) found zero exploitable XSS. BaxBench's oracle prompts cut XSS sharply. The difference is plausibly the methodology (SAST flag vs exploit) and the framework (autoescaping templates). This explanation is inference.
- PortSwigger's logic-flaw examples cover:
  - client-side control trust
  - unconventional input, e.g., a negative transfer amount reversing payment direction
  - skipped workflow steps such as 2FA
  - discount threshold abuse
  - encryption oracles
  - email-parser discrepancies
  - Source: [PortSwigger logic flaw examples](https://portswigger.net/web-security/logic-flaws/examples)

### Inferences
- **Ranking for a Codex-low, Flask, Jinja-autoescape setup** (inference from Tenzai + BaxBench + AutoBaxBench):
  - Highest expected baseline-fail rate and prompt-fixability: SSRF on URL fetch, BOLA on private objects, BOPLA/mass assignment on a profile update, negative/overflow values on a money or quantity action, and missing CSRF/security headers/session hardening.
  - Medium: upload content-type/served-as-HTML and path traversal.
  - Low: SQLi.
  - XSS is medium for weak models, and depends on whether they emit `|safe` or `Markup`.
- **Money/quantity checks have very low false-positive risk.** The oracle is a state read-back (balance went up, stock went negative). The fix is one line of validation that a participant can request in plain words.
- **Concurrency races (double spend) are demo-gold but FP/flaky-prone** with sqlite3 and the single-process Flask dev server, because serialization may hide the race by accident. Inference: treat a race as a bonus, not a core check.
- **Avoid scoring an owner check the spec itself mandates.** It is contract-imposed, so every passing app has it, and it does not differentiate. The current spec says edit/delete is "작성자 또는 관리자만 가능", so the owner check is spec-mandated. This is consistent with the project's minimize-false-positives rule and the removal of the comment/object authorization probes. To make BOLA a participant decision, the spec should describe a private object without stating its access rule (e.g., "users can save private notes"). The judge then checks whether another user can read it. Inference: a "private" label is a functional requirement, not a security hint. It is arguably fair, because a non-owner reading a "private" note is a functional failure too.

### Gaps
- Tenzai's original post, with the names of the 3 app domains and per-category counts, was not retrieved; only press coverage was.
- I found no study of a weak/fast model (low effort) specifically. Generalizing from frontier agents is inference.

## Q4. Is a board a good base, or would a hybrid or another domain be strictly better?

### Takeaway
A pure board is not the best base. Its native decisions (XSS, SQLi) are the ones modern models already get right or that autoescape neutralizes. Its access-control surface is public-by-design, which produced false-positive trouble that led to the probe removal. The best evidence-backed option is a hybrid that keeps the board's familiar public surface and adds:
1. a private-object feature (BOLA),
2. a server-owned field on the profile (mass assignment),
3. one small value-bearing action, e.g., a point/coupon "gift" or "transfer" (business logic).

A full e-commerce domain would add endpoints and contract risk under the ~600 s budget for little extra coverage.

### Cited Findings
- Juice Shop (e-commerce) spreads its challenges across the shop's own objects. Basket: Manipulate/View Basket (access control). Coupon: Forged/Expired Coupon. Feedback and reviews: Forged Feedback/Review, Zero Stars. File upload: size/type. Order: Payback Time (negative-quantity class). Wallet: Wallet Depletion. Deluxe membership: Deluxe Fraud. B2B: a deprecated interface — [Juice Shop companion guide, Part II](https://pwning.owasp-juice.shop/companion-guide/latest/part2/README.html)
- Juice Shop describes itself as "an awareness, training, demonstration and exercise tool" — [Juice Shop guide intro](https://pwning.owasp-juice.shop/companion-guide/latest/introduction/README.html)
- crAPI (car buying + shop + community) places most of its challenges on private objects and money flows:
  - another user's vehicle and mechanic reports
  - deleting another user's video
  - getting an item for free
  - +$1,000 balance
  - coupons
  - SSRF
  - Its listed challenges map little to the community forum itself (fetch model's inference from titles).
  - Source: [crAPI challenges](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md)
- VAmPI's minimal "users + books with a secret" domain is enough for BOLA (another user's book secret), mass assignment and excessive data exposure — [VAmPI](https://github.com/erev0s/VAmPI)
- In BaxBench, the board-like scenarios (Forum, Wiki, Recipes, ProfileCollection) carry only 79/89/20/400/703. Ownership/authorization CWEs (284/863) appear in SecretStorage, ShopOverview, ImageTransfer, UserCreation, CreditCardService and ShoppingCartService instead — [BaxBench v3](https://arxiv.org/html/2502.11844v3)
- AutoBaxBench: more endpoints means a lower secure-and-correct rate. The best result is 25% at Hard (~4.7 endpoints) versus 40% at Medium — [AutoBaxBuilder](https://arxiv.org/html/2512.21132)

### Inferences
**Candidate domains** (evaluated against goals 1–4; all inference):

| Domain | Decisions forced | Notes for this grader |
|---|---|---|
| Board/forum | XSS, SQLi, admin BFLA, plus extras (SSRF preview, upload) | Familiar. Core decisions have low AI-fail rates. Ownership is public. |
| E-commerce/shop | Price/quantity tampering, coupons, BOLA on orders, mass assignment (price) | Best demo value (PortSwigger: "domain that all users will already be familiar with"; [source](https://portswigger.net/web-security/logic-flaws/examples)). Many endpoints (cart, checkout, orders, products, seller role) put the 600 s contract loop at risk. |
| Notes/secret storage | Pure BOLA, data exposure | Tiny and very low FP. Weak on XSS and SSRF unless extras are added. SecretStorage's CWE-522 is not prompt-fixable. |
| Banking/transfer | Negative amount, race double-spend, BOLA on statements | Very understandable. Races are flaky on sqlite and the dev server. |
| File sharing | Upload type, path traversal, BOLA on file ids, share links | Good. File handling is a frequent contract-failure point for weak models. |
| URL shortener/link preview | SSRF, open redirect | One feature. Better as an add-on than a base. |
| Multi-tenant invoice SaaS | Tenant isolation (BOLA), role (BFLA), amount logic | Strongest decision density, but more concepts for both the model and the booth visitor. |

**Concrete argument for the hybrid "board + private + value" design:**
- (a) It keeps every existing probe and the PoC console tabs: XSS, search reflection, SSRF preview, upload, admin, CSRF, session secret.
- (b) It adds three high-AI-miss decisions, each needing only 1–2 endpoints:
  - `POST/GET /notes` (private notes, or private "draft"/"secret" posts) → BOLA by id.
  - A profile update that accepts form fields, where the user row has a `role`/`points` column → mass-assignment probe.
  - `POST /points/send` (send points to another user, `amount`) → negative amount, self-transfer, overdraft.
- (c) Each oracle is a state read-back and needs no heuristic.
- (d) Each fix is one sentence a participant can write: "only the owner can read a note", "never let the client set role/points", "amount must be a positive integer ≤ balance".
- (e) The contract stays near the current endpoint count if a weak feature is dropped in exchange. Candidates are comment edit/delete, sort options, or `/account/password`.

**Why not a full shop:**
- It reproduces the same decision classes with roughly double the endpoints.
- AutoBaxBench shows correctness and security degrade as endpoints grow. A weak model also has a 600 s budget.
- The board's public UI is already understood by booth visitors.

**Why not notes-only:** it loses the XSS, SSRF and upload signals that weak models still miss.

### Gaps
- There is no direct experimental comparison of board vs shop vs notes under the same model. A pilot run (N≈10 generations per variant with the default prompt) would settle it empirically.
- Codex-low's contract pass-time for the extra endpoints is unmeasured.

## Q5. What makes an exploit demo understandable to a non-expert booth visitor?

### Takeaway
Use domains everyone already knows (shop, money, private messages) and exploits whose effect is a visible state change on screen: "I read her private note", "my balance went up", "I became admin", "the server fetched an internal page". Rigorous evidence that live demos change behavior is thin. They are popular, but not shown to work.

### Cited Findings
- PortSwigger chose an online shop for its logic-flaw examples because it is a "domain that all users will already be familiar with" — [PortSwigger](https://portswigger.net/web-security/logic-flaws/examples)
- Juice Shop positions itself as a "demonstration" tool as well as a training one — [Juice Shop guide](https://pwning.owasp-juice.shop/companion-guide/latest/introduction/README.html)
- Live hacking events report high satisfaction. Hochschule Anhalt reported ~200 attendees, and 94% of feedback respondents wanted more such events. This measures satisfaction, not learning — [Hochschule Anhalt](https://www.hs-anhalt.de/en/landingsites/translate-to-english-informationssicherheit/translate-to-english-live-hacking-1-1.html)
- A PACIS 2025 paper plans a live brute-force demo to measure behavioral change, but reports no results in the snippet I saw — [PACIS 2025](https://aisel.aisnet.org/pacis2025/security/security/3)
- CTF education literature:
  - Typical CTFs need "considerable a priori domain knowledge", which excludes novices — [Werther et al., CSET'11](https://static.usenix.org/events/cset11/tech/final_files/Werther.pdf)
  - Course-CTF design hinges on scoring, scaffolding, plagiarism and learning analytics — [Švábenský et al.](https://www.muni.cz/en/research/publications/1570036)

### Inferences
- **Demo-value ranking for booth visitors** (inference):
  - Business logic (negative transfer → balance up) and BOLA (read another person's private note or phone): instant comprehension, no jargon.
  - Admin escalation via mass assignment ("I sent role=admin"): also clear.
  - SSRF: needs a story ("the server fetched its own secret admin page / cloud metadata for me"); show the fetched content.
  - Stored XSS: show a popup or a stolen-cookie banner.
  - CSRF and session-forgery: hardest to explain. Keep them, but give them lower demo priority.
- **Good demo properties:** before/after state, a single request, a familiar object (money, private message, phone number), and the victim's view shown side-by-side with the attacker's.
- **This aligns with the scoring goals:** the most understandable exploits (BOLA, money logic, mass assignment) are also the lowest-FP state read-back oracles and the most-missed by agents (Tenzai).

### Gaps
- I found no controlled study comparing demo types (logic vs injection) for lay comprehension.
- I found no published booth-format secure-coding challenge with a design rationale. The Schmidt/Jörges/Brunner 2026 structured CTF design method was found only as a bibliographic record ([researchr](https://researchr.org/publication/SchmidtJB26/references)).
