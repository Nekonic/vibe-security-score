# Spec size and feature mix vs. LLM generation success, repair-loop cost, and security signal (booth board app)

Research date: 2026-10-24. Scope: how many and which features the booth's Flask + sqlite3 board spec should contain. The setting is `codex exec` with gpt-5.6-luna at low effort, a hidden contract-conformance loop of build + 2–3 `resume` repairs, a 600 s cap, and 5 parallel generations.

How to read this file: **Cited Findings** are measured data from the source named. **Inferences** are my reasoning and are not measured. The user's own data point (full spec, about 20 endpoints, 73.8 s, 397k input / 362k cached / 8.9k output tokens, failed on the admin-seed collision) is quoted from the assignment brief. It is not from an external source.

Correction to an earlier note: `llm_secure_backend_benchmarks.md` gives AutoBaxBench Hard "insecure-of-correct" as 55% (GPT-5) and 68% (Sonnet 4.5). Recomputing from the leaderboard numbers that note itself quotes gives **48% for GPT-5 (1 − 30.7/59.3) and 70% for Sonnet 4.5 (1 − 25.1/82.9)**. The figures below use the recomputed values.

Second caveat: the earlier notes say BaxBench reports an OLS fit of about −0.49 for spec length vs pass@1. I could not confirm a coefficient in this session. The fetched BaxBench v3 text says only that there is "a distinct correlation" and that performance is "negatively correlated" with OpenAPI token count (Fig. 6), with no number in the text. Treat −0.49 as unverified, possibly read off the figure.

---

## Q1. What do benchmarks show about functional pass rate vs number of endpoints / spec length, especially for small or fast models?

### Takeaway
Every benchmark that varies scope shows functional success falling as scope grows. The drop is steep at the hard end, and much steeper for small or cheap models than for frontier models. Combining two working features into one task (WebApp1K-Duo) cut pass@1 from about 0.88–0.95 to about 0.45–0.68.

The current 20-endpoint spec is about 4× the largest benchmark scenario: BaxBench has at most 5 endpoints, and AutoBaxBench Hard averages 4.7. For a weak, low-effort model, that is the regime where single-shot success collapses. Shrinking the spec matters more than adding repair rounds.

### Cited Findings

**BaxBench: spec length**
- Scenarios have 1–5 endpoints, 54 in total, about 2 per scenario.
- OpenAPI specs average about 432 GPT-4o tokens; plaintext specs about 282.
- The paper reports "a distinct correlation" between spec size and difficulty: per-scenario pass@1 is negatively correlated with OpenAPI token count (Fig. 6). It also notes "outlier scenarios with short specifications and only a few endpoints that models strongly struggle with."
- Source: [BaxBench v3](https://arxiv.org/html/2502.11844v3)

**AutoBaxBench: tiers by endpoint count** (Table 1, GPT-4o tokenizer)

| Tier | Avg. endpoints | Avg. spec tokens | Avg. potential CWEs (max) |
|---|---|---|---|
| Easy | 1.0 | 587 | 1.6 (3) |
| Medium | 3.0 | 1006 | 2.7 (6) |
| Hard | 4.7 | 1516 | 3.5 (7) |
| BaxBench (reference) | 1.9 | 430 | 3.3 |

- The §4.3 text says Hard averages "5 API endpoints", which conflicts with the 4.7 in Table 1.
- Source: [AutoBaxBuilder, arXiv 2512.21132](https://arxiv.org/html/2512.21132)

**AutoBaxBench leaderboard by tier** (pass@1 / sec_pass@1, no security prompt)

| Model | Easy | Medium | Hard |
|---|---|---|---|
| GPT-5 | 71.4 / 45.0 | 58.6 / 32.1 | 59.3 / 30.7 |
| Claude Sonnet 4.5 | 80.8 / 35.5 | 84.0 / 40.1 | 82.9 / 25.1 |
| Gemini 3 Pro | — | — | 76.2 / 24.9 |
| GPT-4o (older, weaker) | — | — | 10.7 / 0.5 |

- Source: [baxbench.com/autobaxbuilder](https://baxbench.com/autobaxbuilder) (figures as recorded in the earlier note `llm_secure_backend_benchmarks.md`)

**AutoBaxBench overall (Python-FastAPI), small or older models**
- sec_pass@1 (pass@1): Codestral 10% (31%), Llama3.3-70B 5% (18%), Qwen2.5-72B 5% (16%), Qwen2.5-7B 2% (5%), GPT-4o 16% (41%).
- Frontier comparison: Sonnet 4.5 at about 81–87% pass@1.
- Source: [AutoBaxBuilder Table 2](https://arxiv.org/html/2512.21132)

**WebApp1K vs WebApp1K-Duo** (two atomic tasks from one category randomly merged, so twice the tests and a longer output)
- Single-task pass@1: o1-preview 0.952, o1-mini 0.939, gpt-4o-2024-08-06 0.885, claude-3.5-sonnet 0.881, deepseek-v2.5 0.834, mistral-large-2 0.780.
- Duo pass@1, normalized format: claude-3.5-sonnet 0.679, o1-mini 0.667, o1-preview 0.652, chatgpt-4o-latest 0.531, deepseek-v2.5 0.49, mistral-large-2 0.449.
- Duo pass@1, raw format: 0.32, 0, 0, 0.026, 0.02, 0.02.
- In raw format both o1 models scored **0**. Their first reasoning step committed to splitting the work into two modules, an interface choice that broke every test.
- Source: [Cui, "A Case Study of Web App Coding with OpenAI Reasoning Models", arXiv 2409.13773](https://arxiv.org/html/2409.13773)

**Vibe Code Bench** (100 full-app specs; browser-agent workflows; 5 h cap per app)

Difficulty tiers (Easy / Medium / Hard):

| Model | Easy | Medium | Hard |
|---|---|---|---|
| GPT-5.3-Codex | 81.88% | 57.91% | 13.13% |
| Claude Opus 4.6 | 73.20% | 54.11% | 20.86% |

- Five open-weight models score ≤2.50% on Hard.

Small or fast models (overall accuracy, cost, time):

| Model | Accuracy | Cost | Time |
|---|---|---|---|
| GPT-5 Mini | 14.17% | $0.25 | 11.6 min |
| Gemini 3 Flash | 20.20% | $0.94 | 13.4 min |
| Claude Haiku 4.5 Thinking | 11.39% | — | 12.9 min |
| Grok 4.1 Fast Reasoning | 1.20% | — | 8.8 min |
| GPT-5.3-Codex (top) | 61.77% | — | 75.8 min |

- Among the bottom five models, **73.2% of apps scored zero** and 14.0% failed to start, versus 12.8% zero-score apps for the top five.
- "Model improvement is driven primarily by reducing zero-score apps."
- Source: [Vibe Code Bench, arXiv 2603.04601](https://arxiv.org/html/2603.04601)

**Web-Bench** (50 projects × 20 sequentially dependent tasks)
- The best agent (Claude 3.7 Sonnet, Web-Agent) reached 25.1% Pass@1. Each task averages 3.6 test cases; each project 72.4.
- Source: [Web-Bench, arXiv 2505.07473](https://arxiv.org/abs/2505.07473)

**WebGen-Bench** (websites from scratch, 647 functional test cases)
- Best agent/model pair (Bolt.diy + DeepSeek-R1): 27.8% test-case accuracy.
- Source: [WebGen-Bench, arXiv 2505.03733](https://arxiv.org/html/2505.03733v1)

### Inferences
- The user's spec has about 20 endpoints. That is about 4× AutoBaxBench Hard, and its prose is likely well above 1,500 tokens. No benchmark measures pass rates at this size. Extrapolating from the curves above, a weak, low-effort model should be expected to fail a single shot most of the time. The one observed run fits this: it failed on one interface collision, which is exactly the WebApp1K-Duo "one wrong structural commitment zeroes all tests" pattern.
- Small-model curves fall faster than frontier ones. GPT-4o drops to 10.7% pass@1 on AutoBaxBench Hard while Sonnet 4.5 stays near 83%; GPT-5 Mini scores 14% on Vibe Code Bench. gpt-5.6-luna at low effort is described as an older, weak, fast model, so it should be planned against the small-model curves, not the GPT-5 or Sonnet ones. Luna's actual curve is unmeasured.
- The Vibe Code Bench zero-score finding matters for the booth's gate. For weak models, failure is mostly all-or-nothing per app, not a few broken endpoints. Because the functional gate zeroes the security signal, the spec should minimize the number of things that can produce a zero (boot failure, interface or bootstrap collision), not the raw endpoint count alone.
- **Sizing recommendation (inference):** aim for about 8–12 HTTP routes, in roughly the AutoBaxBench Medium–Hard band per resource, organized as 3–4 resources. Keep the spec at or below about 1,500 tokens, written as an exact table of routes, methods, fields and status codes.

### Gaps
- No public benchmark reports pass@1 for apps of 10–20 endpoints. No benchmark result for gpt-5.6-luna or any "luna" variant was found.
- Per-tier AutoBaxBench numbers for small models exist only in Fig. 6 (an image) and were not extractable.
- I found no FullStack Bench or DevBench analysis of pass rate vs spec length; not researched in depth.

---

## Q2. Which feature types are disproportionately failure-prone for LLM generation? Any data?

### Takeaway
The best quantitative evidence covers three things: **external integrations** (payments and email: steep drops), **authorization logic** (about 20% of behavioral failures), and **file handling plus exact formats and status codes** (named failure classes in BaxBench). Spec items that admit two reasonable encodings (text field vs multipart file, global vs per-route auth) are where benchmark authors themselves found ambiguity.

I found no per-feature data for pagination, HTML-form PUT/DELETE, or JSON+form dual support. Those risks are inferences from mechanics.

### Cited Findings
- **BaxBench manual review of 20 incorrect o1 programs.** The model "often fails on trivial, boiler-plate tasks", listed as:
  - adhering to the API spec requirements
  - "adhering to formats and response codes"
  - "handling files"
  - setting CLI flags
  - producing compilable, executable code
  - Source: [BaxBench v3 §5](https://arxiv.org/html/2502.11844v3)
- **Vibe Code Bench: external service integrations** (test split, GPT-5.3-Codex accuracy)
  - No integration (37 apps): 71.25%
  - Email only (4): 55.00%
  - Stripe only (2): 12.50%
  - Email + Stripe (7): 29.58%
  - All-model average falls from 34.18% (no integration) to 13.49% (both). Open-weight models stay below 8% on apps needing both.
  - Source: [Vibe Code Bench](https://arxiv.org/html/2603.04601)
- **Vibe Code Bench: behavioral failure taxonomy** (apps that started)
  - Missing Feature 46.7%
  - Authorization Issue 20.4%
  - Validation/Policy Block 14.8%
  - Other 10.2%
  - UI Rendering/Navigation 6.0%
  - Data Consistency/Backend Logic 1.9%
  - Source: [Vibe Code Bench](https://arxiv.org/html/2603.04601)
- **Vibe Code Bench: domain complexity** (all-model average)
  - Individual apps 43.01%, Solo Founder 29.94%, Enterprise Tool 18.64%.
  - GPT-5.3-Codex: 76.93% / 62.50% / 49.39%.
  - Source: [Vibe Code Bench](https://arxiv.org/html/2603.04601)
- **AutoBaxBuilder audit of BaxBench ambiguities**
  - **ProfileCollection** (a profile-page upload): "ambiguous whether the profile_page content should be sent as a text field or as a file with MIME type text/html."
  - **Login**: a failing test "arises from the OpenAPI misspecification": a global security definition was applied to `/register`.
  - **ImageConvert** and **Unsubscribe**: tests were adapted because BaxBench's MIME or frame assumptions were wrong.
  - Experts judged 79.17% of scenario specs "not ambiguous" (n=24).
  - Source: [AutoBaxBuilder](https://arxiv.org/html/2512.21132)
- **WebApp1K-Duo**: o1-preview passed every test except one in `addComment_retrieveAllBlogPosts`, where it "did not handle the 500 error case". The author attributes this to a missed expectation (instruction following), not missing knowledge — [arXiv 2409.13773](https://arxiv.org/html/2409.13773)
- **WebApp1K error taxonomy**: the classes include text/attribute mismatch, mock-call count mismatch, uninstalled module, deprecated API (version mismatch), and missing UI element. "93% of error logs contain either a singular error or twin errors." The paper finds models "possess similar underlying knowledge" and differ by "the frequency of mistakes" — [arXiv 2409.05177](https://arxiv.org/html/2409.05177v1)
- **The user's own run** failed on admin bootstrapping: a self-seeded admin/admin caused a 409 on the grader's admin signup. The 409 path also left an open sqlite write transaction, causing "database is locked" on later writes (assignment brief).

### Inferences
Feature-by-feature risk ratings, mostly inference:

- **Outbound HTTP fetch (link_url preview)**: *high generation risk*.
  - It is the closest analog to Vibe Code Bench's external integrations. It needs network egress in the sandbox, timeouts, and HTML parsing, and failures (DNS, timeouts, blocking) hang requests or crash the worker.
  - It is also the only SSRF surface, so it carries unique security signal.
  - Keep it only if the contract makes it *optional at render time*: the post saves even if the fetch fails, and the harness serves a local target to fetch.
- **Multipart upload (post image + avatar)**: *medium-high risk*. BaxBench names "handling files" as a failure class, and the ProfileCollection ambiguity shows the field encoding must be pinned. Two upload features double the risk while mostly duplicating the same CWE family (unrestricted upload, path traversal, stored XSS via SVG/HTML). **Keep one upload, not two.**
- **File serving (`/uploads/<name>`)**: *medium risk*, tied to upload. It is a path-traversal and content-type surface. Pin the URL pattern exactly.
- **Auth/session (signup, login, logout)**: *core and unavoidable*. Every other probe needs a logged-in session, so a failure here zeroes everything. Authorization logic is the second-largest failure class (20.4%). Keep it minimal and pinned.
- **Password change**: *low marginal security value*. It adds a CSRF target and a re-auth decision, but CSRF is already testable on post create and delete. Cut it, or merge it into profile edit.
- **Comments CRUD (many-to-one)**: *moderate risk*. Duo-style combination, plus the `addComment` 500-case miss, plus owner checks. The repo's latest commit `1530d6f` removed object and comment authorization probes, so comment edit/delete may now add generation risk with no scored signal. Keep **comment create and list** as a second stored-XSS sink; drop comment edit and delete.
- **Search**: *low generation risk, high signal* (SQLi plus reflected XSS). Keep.
- **Admin list/role/delete**: *high ambiguity risk* (bootstrapping, as the user's run showed). It is the vertical-privilege surface. Keep at most one admin action (for example delete user or post), and define bootstrap exactly.
- **Profile with phone**: *low value* unless a data-exposure probe exists. Phone is PII and becomes signal only if a probe checks that another user's profile hides it. Otherwise cut.
- **Pagination/sorting**: *no data*. It adds exact-ordering assertions, which are brittle (ties, timestamps). Omit, or require only "newest first" with randomized distinct titles.
- **HTML-form PUT/PATCH/DELETE**: browsers can only send GET and POST from forms. Generated apps will variously use `_method` overrides, POST `/posts/<id>/delete`, or JS fetch. That is a classic two-encodings ambiguity. **Pin POST-based action routes** (for example `POST /posts/<id>/delete`) and do not require true DELETE.
- **JSON + form dual support**: doubles every route's surface and is a two-encodings ambiguity by construction. The earlier note `contract_test_loop_harness.md` recommends content negotiation for exact assertions. If kept, pin a *single* rule, such as "`Accept: application/json` gives JSON with keys X; otherwise HTML", and test it on few routes.

### Gaps
- No benchmark isolates pass rates for multipart upload, outbound fetch, pagination, method override, or dual JSON/form handling. The BaxBench per-scenario pass rates that would show file-handling scenarios (ImageConverter, ZipToTxt, PDFToText, FileSearch) exist only in figures in §D.3 and were not extractable.
- No data on sqlite transaction and locking bugs in generated Flask code. The user's run is the only observation.

---

## Q3. How does adding features change the number of security decisions vs the probability of failing the functional gate? Is there evidence on vulnerability density?

### Takeaway
In AutoBaxBench, going from 1 to 4.7 endpoints roughly doubles potential CWEs per scenario (1.6 → 3.5), which is sublinear: about 0.5 CWE per added endpoint. Over the same range, pass@1 for weaker models falls sharply, and the share of correct apps that are exploitable stays high or rises (GPT-5: 37% → 45% → 48%; Sonnet 4.5: 56% → 52% → 70%).

Because the booth's gate zeroes security on functional failure, the expected security signal per app is roughly P(pass gate) × (number of security decisions). Past a moderate size, adding features lowers it. I found no study that cleanly measures vulnerabilities per endpoint or per KLOC as a function of app size for generated web apps.

### Cited Findings
- **Potential CWEs vs endpoints, AutoBaxBench Table 1**: Easy 1.6 (max 3), Medium 2.7 (max 6), Hard 3.5 (max 7), at 1.0 / 3.0 / 4.7 endpoints. BaxBench scenarios average 3.3 CWEs at 1.9 endpoints, more CWEs per endpoint because its scenarios were hand-picked for security relevance — [AutoBaxBuilder](https://arxiv.org/html/2512.21132)
- **Insecure-of-correct by tier**, computed from leaderboard pass@1 / sec_pass@1 ([baxbench.com/autobaxbuilder](https://baxbench.com/autobaxbuilder)):

  | Model | Easy | Medium | Hard |
  |---|---|---|---|
  | GPT-5 | 1 − 45.0/71.4 = 37% | 1 − 32.1/58.6 = 45% | 1 − 30.7/59.3 = 48% |
  | Sonnet 4.5 | 56% | 52% | 70% |

- **GPT-4o on AutoBaxBench Hard**: 10.7% pass@1 and 0.5% sec_pass@1. A weak model loses the functional gate so often that almost no secure-and-correct signal is left — [baxbench.com/autobaxbuilder](https://baxbench.com/autobaxbuilder)
- **BaxBench**: "Around 50% of the passing programs for each model are exploitable" — [BaxBench](https://arxiv.org/abs/2502.11844)
- **Secure vs exploitable solution length**: secure solutions are on average 5% longer in tokens than correct-but-exploitable ones (10.2% for Express; in Django "the secure solutions are shorter") — [BaxBench v3](https://arxiv.org/html/2502.11844v3)
- **Density literature (not web-app specific)**:
  - A 4,442-task Java study reports about 19.5 issues/KLOC (Claude Sonnet 4) to about 32.5 (OpenCoder-8B), with about 2% of issues being security vulnerabilities — [arXiv 2508.14727](https://arxiv.org/pdf/2508.14727)
  - A small multi-tool study (81 snippets) found the tool generating the *largest* snippets had the fewest vulnerabilities — [arXiv 2605.23091](https://arxiv.org/pdf/2605.23091)
  - Neither measures density vs number of endpoints.

### Inferences
- **Expected-signal model (inference).** Let D(n) be the number of distinct scored security decisions and P(n) the probability the gate passes after the repair loop. AutoBaxBench gives D growing about +0.5 per endpoint, sublinear because features reuse CWE families. For weak models P falls steeply: GPT-4o goes from 41% overall to 10.7% on Hard, and Vibe Code Bench small models score 1–20%. So D × P peaks at a moderate size.
- The repair loop raises P, so the peak moves right but does not disappear. Vibe Code Bench's r = 0.72 between self-testing and accuracy suggests execution feedback is the strongest lever.
- What raises signal is **distinct CWE families**, not endpoints. A second upload, a second CRUD resource, or extra admin actions mostly repeat families already covered. Prefer one route per family:
  - XSS sink: post body; comment body
  - Reflected XSS + SQLi: search
  - CSRF: post create and delete
  - IDOR / ownership: post edit and delete
  - Vertical privilege: one admin action
  - Upload: one upload
  - SSRF: link preview, optional
  - Session, secret and debug configuration: free, no extra routes
- That set covers roughly 8–9 families with about 10–12 routes. The current about-20-endpoint spec adds roughly 8 routes (password change, avatar upload, comment edit/delete, profile/phone, two more admin actions) that mostly duplicate covered families while adding interface-collision and ambiguity risk.
- The booth needs both secure and insecure outcomes to occur, so the prompt can make a difference. AutoBaxBench shows about 37–70% of correct apps exploitable even at the frontier, so a small spec still leaves plenty of vulnerability headroom. Cutting features does not remove the challenge.

### Gaps
- No study measures vulnerabilities per endpoint or per app as a function of endpoint count for generated web apps. The tier CWE counts are *potential* CWEs per scenario, not found vulnerabilities per app.
- Per-tier sec_pass@1 for small models is unavailable as text.

---

## Q4. Which requirements are notorious for spec ambiguity in generated CRUD apps, and how do benchmarks pin them?

### Takeaway
Benchmarks reduce ambiguity in three ways:
1. **Machine-readable specs** (OpenAPI: +6.8 to +9.3 pp pass@1 over plaintext).
2. **A fixed environment contract**: port, DB filename, secret env var, scaffold.
3. **Tolerant tests**: status-code classes such as 2xx instead of exact codes, and property checks instead of exact-match bodies.

Spec authors themselves still find a few percent of tests wrong and about 20% of scenarios at least partly ambiguous. Admin bootstrapping and duplicate-user conflict behavior are not pinned by any benchmark I found. The booth has to pin them itself.

### Cited Findings
- **OpenAPI vs plaintext specs**: pass@1 gains of +8.1% (o3-mini), +9.3% (GPT-4o), +6.8% (Claude-3.5 Sonnet); sec_pass@1 gains of +2.8%, +3.2%, +4.8%. OpenAPI makes the task "significantly less error-prone" — [BaxBench v3](https://arxiv.org/html/2502.11844v3)
- **BaxBench's fixed environment contract**:
  - Listen on port 5000.
  - "You must create and use an sqlite3 database named ./db.sqlite3".
  - The secret comes from `APP_SECRET`.
  - The allowed packages are listed.
  - Fixed scaffolds and run commands for multi-file frameworks.
  - Source: [BaxBench v3 App. C](https://arxiv.org/html/2502.11844v3) (via earlier note)
- **Status codes as given in OpenAPI**: specs list explicit response codes, for example Calculator's 200 and 400 "Invalid input". AutoBaxBuilder's generated tests use status-code *categories*. Its RefineTests step loosens over-specific assertions: in SVGBadgeForge an exact-match check became a property check, and one test accepts any 2xx — [BaxBench v3](https://arxiv.org/html/2502.11844v3); [AutoBaxBuilder](https://arxiv.org/html/2512.21132)
- **Ambiguities the benchmark authors found**:
  - Multipart file vs text field (ProfileCollection).
  - Global auth requirement leaking onto `/register` (Login).
  - MIME and media assumptions (Unsubscribe, ImageConvert).
  - 2 erroneous BaxBench tests and 2 ambiguous specs among 4 outliers.
  - Experts rated 79.17% of scenarios "not ambiguous".
  - Source: [AutoBaxBuilder](https://arxiv.org/html/2512.21132)
- **Interface naming as a total-failure mode**: WebApp1K-Duo raw format (export names TaskA/TaskB) scored 0 for both o1 models but 0.65–0.67 once normalized to a single `App` import — [arXiv 2409.13773](https://arxiv.org/html/2409.13773)
- **Error-path omission**: o1-preview missed only the 500-error expectation in a comment task — [arXiv 2409.13773](https://arxiv.org/html/2409.13773)

### Inferences
These ambiguities need explicit pins in the booth spec, ranked by how likely they are to cause a gate failure:

1. **Admin bootstrapping.** This caused the observed failure. Pin one mechanism exactly:
   - for example, "the app MUST NOT create any user at startup; the first account created via `POST /signup` becomes admin", or
   - "a user named in env `ADMIN_USERNAME` becomes admin on signup".
   - Also forbid seeded accounts outright. Seeded admin/admin is also a hardcoded-credential vulnerability, so this pin removes an uncontrolled false-positive or false-negative source.
2. **Duplicate signup** must return a pinned status (409 or 400, or any 4xx), and must not break later writes. Add a contract test that does duplicate signup → then a normal post create. That catches the leaked-transaction "database is locked" class. Also pin `sqlite3` usage in the spec: one connection per request, closed in teardown, so the model gets a concrete pattern.
3. **Redirect vs 200/201 after form POST.** Accept 200/201/302/303 for HTML form submissions, the class-tolerant approach. Assert on observable state afterwards (follow the redirect, then GET the list) rather than on the exact code.
4. **Delete and update in HTML forms.** Pin POST action routes. Never require DELETE/PUT from forms.
5. **JSON vs form.** Pin one content-negotiation rule, or make the contract form-only plus HTML checks with only "contains the marker" assertions. Avoid requiring both encodings on every route.
6. **Upload encoding.** Pin a field name (`image`), `multipart/form-data`, the URL where the file is served back, and the allowed extensions *only if* they are not themselves the security decision. Per the user's false-positive memory note, a contract constraint must never be the thing that is graded.
7. **IDs.** Do not assume id=1 is admin or that ids are sequential. The test harness should read ids from responses or redirects. This matches the user's earlier removal of the sequential-id penalty.
8. **Error codes.** Specify a small set (401/403 for not logged in or not allowed, 404 for missing) and test them as classes (any 4xx where sensible). WebApp1K-Duo shows error-path expectations are the ones weak models drop.

### Gaps
- No benchmark found that specifies admin bootstrapping, duplicate-user status, or redirect-vs-200 conventions. These pins are the booth's own design work.
- How ambiguous a free-form participant prompt is relative to the spec is unmeasured.

---

## Q5. Time and token cost per repair iteration for agentic CLIs on small apps; how cached input tokens behave on resume

### Takeaway
Agentic coding cost is dominated by **input tokens** (re-sent context), not output. For OpenAI models, re-sent prefixes are cached: up to 95% discount, minimum lifetime 30 minutes for GPT-5.6 and later, minimum cacheable length 1,024 tokens. A `codex exec resume` within the booth's 600 s window should therefore hit the cache for nearly the whole prior context.

I found no public measurement of per-iteration time for `codex exec resume` on small apps. Based on the user's 73.8 s single-shot run, a repair round plausibly costs about 15–45 s of model time plus harness test time. That fits 1 build + 2–3 repairs inside 600 s with margin, but needs measurement.

### Cited Findings
- **`turn.completed` usage fields.** The event carries `input_tokens`, `cached_input_tokens`, `output_tokens`, and `reasoning_output_tokens`. The docs' sample shows `"input_tokens":24763,"cached_input_tokens":24448,"output_tokens":122`. Resume is via `codex exec resume --last` or `codex exec resume <SESSION_ID>` — [OpenAI Codex non-interactive docs](https://developers.openai.com/codex/noninteractive)
- **OpenAI prompt caching**
  - "The minimum cacheable prompt length is 1,024 tokens for GPT-5.6 and later."
  - "Cache reuse requires the entire rendered prefix to match."
  - In-memory entries remain "around 5 to 10 minutes of inactivity, up to one hour". For GPT-5.6 and later the default minimum lifetime is 30 minutes, with a 12-hour option in the Responses API.
  - Cached input is "discounted up to 95%", and reuse can reduce time to first token.
  - Source: [OpenAI prompt caching guide](https://developers.openai.com/api/docs/guides/prompt-caching)
- **Bai et al. 2026, SWE-bench Verified, 8 frontier models**
  - Agentic tasks use about 1,000× more tokens than code chat or reasoning; input tokens drive cost.
  - Runs on the same task vary by up to **30×** in tokens.
  - More tokens do not reliably mean higher accuracy; accuracy peaks at an intermediate cost.
  - Self-predictions of token use correlate at most 0.39.
  - Source: [Stanford Digital Economy Lab, arXiv 2604.22750](https://digitaleconomy.stanford.edu/publication/how-do-ai-agents-spend-your-money-analyzing-and-predicting-token-consumption-in-agentic-coding-tasks/)
- **Cache economics in Claude Code** (secondary summary of Weinberger & Hozez 2026, arXiv 2607.12161)
  - 2,848 billed sessions; about 4.5 assistant turns per session.
  - Cache reads and writes are about 87% of reconstructed cost. Cache writes cost 1.25× input and cache reads 0.1× (Anthropic pricing).
  - Compaction rewrites the prefix and invalidates the cache.
  - The blog's claim that `--resume` keeps the cached prefix is uncited.
  - Source: [Vaughan blog summary](https://codex.danielvaughan.com/2026/07/28/token-reduction-is-not-cost-reduction-prompt-cache-economics-codex-cli-tool-output-compaction-billing/); primary paper not verified.
- **Vibe Code Bench wall-clock per full app** (5 h cap, much larger apps):
  - GPT-5 Mini 11.6 min, Gemini 3 Flash 13.4 min, Grok 4.1 Fast 8.8 min, GPT-5.3-Codex 75.8 min, Opus 4.6 21.3 min.
  - Browser self-test calls correlate with accuracy (r = 0.72; partial r = 0.72 controlling for latency). Edit calls correlate at only r = 0.09.
  - Source: [Vibe Code Bench](https://arxiv.org/html/2603.04601)
- **Repair-loop gains** (via earlier note `contract_test_loop_harness.md`): Self-Debugging gains up to 12% with unit-test feedback; AlphaCodium raised GPT-4 from 19% to 44% on CodeContests through test-driven iteration; most gain comes in the first 1–2 rounds — [Self-Debugging, ICLR 2024](https://iclr.cc/virtual/2024/poster/18816); [AlphaCodium](https://www.arxiv.org/pdf/2401.08500)

### Inferences
- **User data point.**
  - 397k input tokens with 362k cached (91%) over a single run means the session re-sent a growing context across many agent turns. That is consistent with roughly 15–25 tool-call turns at about 15–30k context each; the turn count is not measured.
  - 8.9k output tokens in 73.8 s works out to about 120 output tok/s if all wall time were decoding. That exceeds the benchmarked 99 tok/s, so either reasoning tokens are counted separately or tool time overlapped. Check `reasoning_output_tokens` in the JSONL.
- **Per-repair-round estimate.**
  - A resume adds a failure summary (about 0.5–2k tokens) on top of the cached prefix.
  - A targeted fix is plausibly 1–3k output tokens plus several read/edit/run turns, so about 15–45 s of model time.
  - Add harness time for boot + contract suite, perhaps 5–20 s per round.
  - Budget estimate: 74 s build + 3 × (45 + 20) s ≈ 270 s worst-typical, inside 600 s. This assumes the 30× run-to-run variance (Bai et al.) does not hit. Keep a hard per-round timeout (for example 150 s) so one runaway session cannot eat the cap.
- **Smaller spec lowers per-round cost too.** Fewer files and routes mean less context re-read per turn and shorter failure summaries. With 5 parallel sessions, input tokens per minute can hit organization rate limits, and it is unverified whether cached tokens count toward TPM. Cutting the spec from about 20 to about 10–12 routes plausibly cuts input tokens per run roughly in proportion to code size.
- **Resume vs fresh session.** Resuming preserves the identical prefix, so it should hit the cache: GPT-5.6+ has a ≥30 min lifetime and the booth's rounds are seconds apart. A fresh `codex exec` per repair would re-pay the full uncached prefix and lose the conversation. Use `resume <thread_id>`, not `--last`, with 5 parallel sessions (per the earlier note). Avoid anything that triggers auto-compaction mid-loop, since it invalidates the cache.

### Gaps
- No public measurement of `codex exec resume` latency, tokens per repair round, or cache hit rate on the first resumed turn. Measure from the JSONL `turn.completed` events in booth dry runs.
- Whether gpt-5.6-luna is in the "GPT-5.6 and later" caching tier (1,024-token minimum, 30 min default lifetime) is unconfirmed.
- No data on whether cached input tokens count toward OpenAI TPM rate limits under 5-way parallelism.
- Aider and Claude Code per-iteration data on small apps were not found beyond the Claude Code cache-economics summary.
