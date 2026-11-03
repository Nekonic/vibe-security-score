# Repo porting assessment: what a framework switch costs, and what it does to grading accuracy (vibe-security-score)

Scope: I read the code in this worktree (`/Users/nekonic/Documents/GitHub/vibe-security-score/.claude/worktrees/project-understanding-909a3d`). Every "Source" is a repo path with line numbers, relative to that root. I fetched only a few web pages, all to confirm framework or tool defaults (osv-scanner, Django, Express, Next.js, Rails, Laravel, Spring, Starlette). Framework facts I did not confirm this session are labelled "(general knowledge, unverified)" and kept in Inferences.

---

## Q1. Which checks are framework-agnostic, and which are bound to Flask? (file:line)

### Takeaway
About half of the score (roughly 52 of 100 rubric points) comes from HTTP probes that would work against any framework if the contract is kept. About 28 points are regex static checks written for Python/Flask syntax, 10 points are the pip/PyPI-bound dependency pool, and 10 points (`verbose_errors`) are an HTTP probe whose signatures are Python/Werkzeug-only. Three critical penalties come from Python-only static regexes: `debug_true` −20, `weak_default_secret` −15 and `csrf_protection` −6. The live session-forgery PoC is hard-wired to Flask's cookie signer.

### Cited Findings

**(a) Framework-agnostic HTTP probes: reusable if the HTTP contract holds**
- `functional` is the gate. It runs signup → login → wrong password → create post over HTTP — [scoring/checks/A07_authentication_failures.py:22-131](scoring/checks/A07_authentication_failures.py). It is agnostic, but it relies on the heuristic auth-state oracle `_looks_like_login_form` (lines 87-89) and on discovering the id from login JSON (lines 109-114).
- `weak_password_policy` — [A07:135-158](scoring/checks/A07_authentication_failures.py); `auth_session_management` (old-password check plus logout invalidation) — [A07:166-254](scoring/checks/A07_authentication_failures.py). Both are agnostic and use the login-form oracle.
- `idor_profile` — [A01:56-104](scoring/checks/A01_broken_access_control.py). It is agnostic. It brute-forces user ids 1..10 when login did not return one ([A01:130-140](scoring/checks/A01_broken_access_control.py)).
- `access_control_admin` [A01:144-179], `privilege_escalation` [A01:196-217] and `admin_user_mgmt` [A01:285-307] are agnostic, but all three decide via the keyword heuristic `_looks_like_admin` — [scoring/shared/http.py:295-322](scoring/shared/http.py).
- `ssrf` is a live callback probe — [A01:245-281](scoring/checks/A01_broken_access_control.py), plus [scoring/shared/ssrf_callback.py](scoring/shared/ssrf_callback.py). Fully agnostic.
- `sqli`: sqlmap runs against `/search?q=`, `/posts?sort=` and `/posts?page=` — [scoring/shared/sqlmap.py:51-57](scoring/shared/sqlmap.py). The built-in oracle is at [A05_injection_sql.py:158-250](scoring/checks/A05_injection_sql.py). The tool is agnostic, but the error signatures are SQLite/Python strings (`"sqlite3"`, `"operationalerror"`, `"traceback (most recent call last)"`, `"psycopg2"`) — [A05_injection_sql.py:98-102](scoring/checks/A05_injection_sql.py).
- `stored_xss` [A05_injection_xss.py:186-292] and `reflected_xss` [A05_injection_xss.py:296-312] are agnostic, but they only judge responses whose Content-Type contains "html" (`_is_html_response`, [http.py:325-331](scoring/shared/http.py); used at xss.py:213-214, 232, 249, 271, 303-304).
- `unrestricted_upload` — [A08_integrity_failures.py:73-133](scoring/checks/A08_integrity_failures.py). It is agnostic, but it finds the served URL with heuristics: JSON keys plus a `/static|uploads|media/...` regex ([A08:163-186](scoring/checks/A08_integrity_failures.py)).
- `rate_limiting` — [A06_insecure_design.py:16-38](scoring/checks/A06_insecure_design.py). It is agnostic, but besides 429/423 it accepts lockout keywords in the body (line 13).
- `transport_security` checks runtime headers and cookie flags on `GET /posts` after login — [A02:79-108](scoring/checks/A02_security_misconfiguration.py). Agnostic.
- CSRF handling for every grader POST lives in [scoring/shared/csrf.py](scoring/shared/csrf.py). It recognizes the token *names* `_csrf`, `csrf_token`, `csrfmiddlewaretoken` and `authenticity_token` (line 29), but it always *sends* the field `csrf_token` and the header `X-CSRF-Token` (lines 22-23, 80-81).

**(b) Python/Flask-specific static checks: each must be rewritten per language (all regex over `*.py` plus `templates/*.html`)**
- The static phase reads only `*.py` files and `templates/` with `.html/.jinja` extensions — [scoring/engine/runner.py:25-28, 41-48](scoring/engine/runner.py).
- `csrf_protection` looks for the markers `csrf_token|CSRFProtect|flask_wtf|WTF_CSRF|csrf.protect|X-CSRF|csrf_protect` or `SESSION_COOKIE_SAMESITE=Lax/Strict` — [A01:32-52](scoring/checks/A01_broken_access_control.py). It carries critical −6 ([config/scoring.yaml:71](config/scoring.yaml)). The docs call it a presence heuristic, not proof of server-side verification — [scoring/README.md:157-159](scoring/README.md).
- `debug_true` matches the regex `debug\s*=\s*True|DEBUG\s*=\s*True|['DEBUG']=True` — [A02:17-34](scoring/checks/A02_security_misconfiguration.py). Critical −20, justified as "Werkzeug interactive debugger = RCE" ([scoring.yaml:68, 78, 88](config/scoring.yaml)).
- `security_headers` needs a header name plus a Flask mechanism (`after_request|Talisman|.headers[...]`) anywhere in the source — [A02:38-70](scoring/checks/A02_security_misconfiguration.py).
- `hardcoded_secret` targets `SECRET_KEY`/`secret_key`/`config['SECRET_KEY']` with an `os.environ`/`getenv` exemption — [A04:21-62](scoring/checks/A04_cryptographic_failures.py).
- `weak_default_secret` matches `environ.get|getenv('...SECRET...', '<literal>')` — [A04:92-112](scoring/checks/A04_cryptographic_failures.py). Critical −15, applied on the static match alone (not gated on the PoC; [scoring/engine/aggregate.py:66-81](scoring/engine/aggregate.py)).
- `password_hashing`: any line mentioning `bcrypt|argon2|scrypt|pbkdf2|generate_password_hash|check_password_hash|passlib` counts as strong; `md5(`/`sha1(` on a password line counts as weak; `obj.password ==` counts as plaintext — [A04:116-165](scoring/checks/A04_cryptographic_failures.py).
- `cookie_flags` checks the Flask config names `SESSION_COOKIE_HTTPONLY/SECURE/SAMESITE`, and assumes HttpOnly is on whenever Flask `session` is imported — [A04:169-212](scoring/checks/A04_cryptographic_failures.py).
- `sql_parameterization` looks for Python `.execute(`/`.executescript(` whose first argument is an f-string, `%`, `+` or `.format` — [A05_injection_sql.py:28-78](scoring/checks/A05_injection_sql.py).
- `xss_template` flags `render_template_string`, Jinja `|safe`, `autoescape=False` and `{% autoescape false %}`, and exempts custom escaping filters found via Flask's `@app.template_filter`/`add_template_filter` — [A05_injection_xss.py:42-161](scoring/checks/A05_injection_xss.py).
- `csp` looks for the string `Content-Security-Policy`, `Talisman(` or a meta `http-equiv` anywhere — [A05_injection_xss.py:167-182](scoring/checks/A05_injection_xss.py). The header name is language-neutral; `Talisman` is Flask-only.
- `insecure_deserialization` matches `pickle.loads`, `yaml.load` and `eval/exec` near `request.` — [A08:18-50](scoring/checks/A08_integrity_failures.py).
- `security_logging` looks for `logging.basicConfig|getLogger|app.logger|dictConfig` plus logger calls — [A09_logging_failures.py:13-28](scoring/checks/A09_logging_failures.py).
- Language-agnostic external tools, report-only (weight 0): `semgrep` with ruleset `p/security-audit` — [sast.py:14-29](scoring/checks/sast.py), [scoring.yaml:255-259](config/scoring.yaml); and `gitleaks_secrets` — [A04:216-233](scoring/checks/A04_cryptographic_failures.py).

**(c) Bound to the Flask runtime or the Python ecosystem**
- `session_forgery` builds a Flask app in-process and signs a cookie with `SecureCookieSessionInterface().get_signing_serializer` — [A04:305-322](scoring/checks/A04_cryptographic_failures.py). It forges guessed payload keys `user_id/uid/id/is_admin/role` (lines 267-268) and assumes admin is user id 1 ([scoring.yaml:523-528](config/scoring.yaml)). The PoC console replays that cookie on the stated premise that "Flask session cookies have no server state" — [grader/submissions/poc.py:21-45](grader/submissions/poc.py).
- `cve` parses only `requirements.txt` `name==ver` lines — [A03:38-64](scoring/checks/A03_supply_chain.py). It runs osv-scanner with `--lockfile requirements.txt:` — [A03:325-329](scoring/checks/A03_supply_chain.py). `dynamic_cve` reads the resolved versions with `pip freeze` inside the container — [A03:436-465](scoring/checks/A03_supply_chain.py), [scoring/shared/sandbox.py:136-150](scoring/shared/sandbox.py). Aggregation prefers the resolved result over the static one — [aggregate.py:14-17](scoring/engine/aggregate.py).
- `typosquatting` uses PyPI name normalization (`-_.`) and the snapshot `data/popular_packages.json` — [A03:178-225](scoring/checks/A03_supply_chain.py). `hallucinated_package` queries the PyPI JSON URL — [A03:370-397](scoring/checks/A03_supply_chain.py).
- `verbose_errors` is an HTTP probe, but its leak signatures are `"traceback (most recent call last)"`, `"werkzeug debugger"`, `"/__debugger__"`, `"sqlalchemy"` and `'file "/app'` — [A10_exceptional_conditions.py:15-18](scoring/checks/A10_exceptional_conditions.py).
- The `debug_true` PoC template detects the Werkzeug console (`__debugger__`, `debugger.js`) — [poc.py:185-221](grader/submissions/poc.py).
- Sandbox:
  - The image is `python:3.11-slim` with Flask and gunicorn preinstalled — [sandbox/Dockerfile:3-9](sandbox/Dockerfile).
  - `sitecustomize.py` monkeypatches `flask.Flask.run` to bind 0.0.0.0:APP_PORT, turn off the reloader and drop `ssl_context` — [sandbox/sitecustomize.py:6-21](sandbox/sitecustomize.py).
  - The entrypoint runs `pip install -r requirements.txt`, then `python app.py|wsgi.py|main.py` — [sandbox/entrypoint.sh:24-37](sandbox/entrypoint.sh).
  - `Sandbox` refuses to boot without `app.py/wsgi.py/main.py` — [scoring/shared/sandbox.py:51-55](scoring/shared/sandbox.py).
  - Boot is detected by polling `GET /posts` — [sandbox.py:93-109](scoring/shared/sandbox.py).
- The harvest globs are Python/Flask-shaped: `app.py, wsgi.py, main.py, requirements.txt, .env, templates/**/*, static/**/*, *.py` — [config/scoring.yaml:224-225](config/scoring.yaml).
- The system prompt is Flask-specific throughout: `python app.py`, `init_db(); app.run()`, `secrets.token_hex`, Flask 3.x removed APIs, "로그인은 Flask session을 사용한다" (log in with Flask session), uv venv self-test — [config/default_prompt.md:3-32, 47, 117-130](config/default_prompt.md).
- Test fixtures are Flask apps: `samples/secure_board`, `samples/vulnerable_board` ([docs/ARCHITECTURE.md:206-207](docs/ARCHITECTURE.md)), plus `scoring/tests/test_static.py` etc.

### Inferences
- **Approximate weight split** (my arithmetic from [config/scoring.yaml:12-50, 303-528](config/scoring.yaml); categories sum to 100; checks are weighted within each category):
  - Python-static regex: about 28.2 points (security_config 40/44×10 = 9.1; xss 8/21×10 = 3.8; sqli 6/16×15 = 5.6; auth 4/28×15 = 2.1; ai_security 16/21×10 = 7.6).
  - Dependency ecosystem: 10 points.
  - `verbose_errors` (signature-bound): 10 points.
  - Agnostic dynamic: about 51.8 points (functional 20 + the rest).
  - Skipped checks are excluded and the rest renormalized, so these are nominal.
- Critical penalties that depend on Python-only regexes total 41 points (`debug_true` 20, `weak_default_secret` 15, `csrf_protection` 6). `hardcoded_secret` (15) depends on the Flask-only forge PoC ([aggregate.py:73-77](scoring/engine/aggregate.py)). So a framework switch without rewriting these silently removes most critical penalties. That would make the grader systematically lenient: false negatives (FN).
- The PoC console is mostly agnostic: `poclib` and the attack image need only `requests` ([sandbox/attack/Dockerfile:10-15](sandbox/attack/Dockerfile)). Only the `debug_true` and forgery-replay templates are Flask-bound. The other eight templates are plain HTTP.
- Some PoC templates use cruder oracles than the scorer. `stored_xss` and `reflected_xss` check whether `"<script>"` is anywhere in the page ([poc.py:129, 144](grader/submissions/poc.py)); `access_control_admin` checks for `"admin" in text` ([poc.py:111](grader/submissions/poc.py)). In any framework whose layout ships its own `<script>` tags (Next.js, Rails/Turbo, Laravel/Vite), these PoCs would falsely print "EXPLOITED". This is independent of the contract and should be fixed in any case.

### Gaps
- I did not run the test suite or measure real per-check skip rates on generated apps, so I cannot say how often each heuristic actually misfires in production data.

---

## Q2. Which FP/FN sources come from contract ambiguity (a conformance loop would fix them), and which come from the framework or language (only switching or rewriting fixes them)?

### Takeaway
Most current FP/FN *machinery in the dynamic probes* exists to guess the app's interface: field names, ids, served URLs, "am I logged in?", "is this an admin page?". An exact contract enforced by a generate-until-conformant loop removes nearly all of that guesswork, independent of framework. It can even make the removed BOLA probes viable again. What it cannot fix:
- the static regex heuristics, which check for presence, not behavior;
- signatures and mechanisms tied to the language (error traces, cookie forging, CVE ecosystem);
- the loss of score variance when a framework's secure defaults make a check always pass.

### Cited Findings

**Heuristics that exist because of contract ambiguity (a conformance loop can eliminate them)**
- *Field-name spraying.* Every post sends `title, content, body, text` because "Apps split on the post-body field name" — [scoring/shared/http.py:57-61](scoring/shared/http.py). Signup and login send both `username` and `phone` — [http.py:45-54](scoring/shared/http.py). Usernames and phones are randomized per run to avoid 409 collisions with demo seed users — [http.py:128-137](scoring/shared/http.py).
- *Post-id discovery.* JSON keys `id/post_id/pk`, else a regex over `/posts/(\d+)` in the listing HTML — [http.py:64-86](scoring/shared/http.py).
- *User-id discovery.* Login JSON keys `id/uid/user_id` ([A07:109-114](scoring/checks/A07_authentication_failures.py)), else `GET /users/1..10`, matching the phone digits ([A01:130-140](scoring/checks/A01_broken_access_control.py)).
- *Auth-state oracle.* `_looks_like_login_form` means a password input in the response = not logged in ([http.py:89-98](scoring/shared/http.py)). It is used by functional, the SQLi auth-bypass, weak_password_policy and auth_session_management. `_sm_can_create` exists because apps answer `200 {"error":"login required"}` ([A07:208-217](scoring/checks/A07_authentication_failures.py)).
- *Admin-content oracle.* `_looks_like_admin` combines a keyword list (`관리자`, `admin dashboard`, `is_admin`, `post_count`…), an `<h1>Admin</h1>` regex, a deny-phrase veto and JSON `users` list — [http.py:295-322](scoring/shared/http.py). The contract doc admits that without a list marker this is "휴리스틱 추측 → FP/FN" (a heuristic guess that produces FP/FN) — [docs/APP_CONTRACT.md:166](docs/APP_CONTRACT.md).
- *IDOR "control broken = 60".* This partial score exists for apps that do not render the owner's phone — [A01:85-99](scoring/checks/A01_broken_access_control.py), [scoring.yaml:433](config/scoring.yaml).
- *Served-upload URL discovery.* It tries 4 sink/field combinations, then JSON keys, then a regex — [A08:136-186](scoring/checks/A08_integrity_failures.py).
- *Rate-limit signal.* 429/423 or keyword phrases like "too many", "잠금" (locked) — [A06:13, 36](scoring/checks/A06_insecure_design.py).
- *Removed probes.* `object_authorization` (post edit/delete BOLA) and `comment_authorization` were removed. Both "depended on pinning a post/comment id and on an owner positive control landing, so an app whose response shape hid those ids was accused or skipped on grader-side discovery failures" — [A01:9-13](scoring/checks/A01_broken_access_control.py); [docs/APP_CONTRACT.md:97-103, 131-134](docs/APP_CONTRACT.md); [config/scoring.yaml:455-462](config/scoring.yaml). Removed in commit 1530d6f, which deleted 712 lines including two test files (`git show 1530d6f --stat`).
- The contract doc already states the principle: almost all FP/FN arise where "판정 신호가 휴리스틱" (the verdict signal is a heuristic). Promoting the marker into the contract turns the heuristic into a deterministic verdict — [docs/APP_CONTRACT.md:19-20, 26-33](docs/APP_CONTRACT.md).
- *XSS skip on JSON.* An app that returns JSON for `/posts`, `/posts/<id>` or `/search` makes both XSS probes skip judgment (`continue`), and the result is credited as defended — [A05_injection_xss.py:213-214, 303-304, 290-292](scoring/checks/A05_injection_xss.py). This is ambiguity in the representation contract (HTML or JSON?). The current prompt only says "JSON과 form 요청을 모두 지원한다" (support both JSON and form requests) for *requests* — [default_prompt.md:44](config/default_prompt.md).

**Heuristics caused by the framework or language, or by static analysis itself (a conformance loop cannot fix them)**
- *Static presence regexes.* `csrf_protection` credits any occurrence of a token string even without server-side verification ([README.md:157-159](scoring/README.md)). `password_hashing` credits any mention of "bcrypt" ([A04:116-163](scoring/checks/A04_cryptographic_failures.py)). `security_headers` needs a name plus any mechanism anywhere ([A02:47-63](scoring/checks/A02_security_misconfiguration.py)). `security_logging` takes any logger call ([A09:13-28](scoring/checks/A09_logging_failures.py)).
- Previous static FP fixes show the pattern:
  - plaintext compare narrowed to stored credentials — [A04:122-130](scoring/checks/A04_cryptographic_failures.py);
  - `Secure=False` / `SameSite=None` no longer credited (commit b19d8ce) — [A04:178-185](scoring/checks/A04_cryptographic_failures.py);
  - ORDER BY / `.join(` f-strings exempted — [A05_injection_sql.py:57-71](scoring/checks/A05_injection_sql.py);
  - escape-then-`|safe` and custom escaping filters exempted — [A05_injection_xss.py:46-53, 89-123](scoring/checks/A05_injection_xss.py).
- *Static `ssrf_sink` removed.* "cannot separate a guarded implementation from an exploitable one without real dataflow analysis" — [A01:5-7](scoring/checks/A01_broken_access_control.py), [scoring.yaml:391-396](config/scoring.yaml), [README.md:263-268](scoring/README.md). This limit is inherent to static analysis and applies in every language.
- *Error signatures.* `verbose_errors` and the SQLi `error_leak` rely on Python/Werkzeug/SQLite strings — [A10:15-18](scoring/checks/A10_exceptional_conditions.py), [A05_injection_sql.py:98-102](scoring/checks/A05_injection_sql.py).
- *Session forgery.* Needs Flask importable on the grader host. Payload keys are guessed (`user_id/uid/id…`) and admin = id 1 — [A04:257-302](scoring/checks/A04_cryptographic_failures.py).
- *Sandbox boot slips handled as non-security.* `mkdir logs` before boot ([sandbox/entrypoint.sh:18-22](sandbox/entrypoint.sh)); `ssl_context` stripped ([sitecustomize.py:14-18](sandbox/sitecustomize.py)); the Secure flag cleared on cookies so they flow over HTTP ([http.py:167-175](scoring/shared/http.py)); the token kept as a fallback after a validation 400 ([csrf.py:101-113](scoring/shared/csrf.py), [http.py:242-256](scoring/shared/http.py)).
- *Typosquatting false positives.* Fixed by tightening edit distance from 2 to 1 — [scoring.yaml:408-416](config/scoring.yaml).

### Inferences
- **What a conformance loop fixes, if it tests only positive paths:**
  - `POST /posts` returns `201 {"id":n}`.
  - signup/login return `{"id":n}`.
  - `GET /me` (or similar) returns `200 {id, username}` when authenticated and 401 otherwise. This replaces `_looks_like_login_form` with a deterministic auth oracle for functional, weak_password_policy, sqli auth-bypass and auth_session_management.
  - `GET /admin/users` as admin returns a machine marker, e.g. JSON `{"users":[...]}` or a fixed `data-*` attribute. This replaces the `_looks_like_admin` keywords; a denial page can never carry the marker.
  - avatar/upload return `{"url": ...}`.
  - `/search` and `/posts/<id>` must return `text/html` with q echoed and posts listed.
  - exact field names (`content`, not body/text).

  Together these remove the spraying, id brute-forcing, URL-regex discovery and HTML/JSON skip paths. They also remove the stated reason for deleting `object_authorization`/`comment_authorization`: the loop guarantees an owner can edit and delete, and that ids are returned. That makes those probes deterministic, though note the repo currently says "재도입 금지" (do not reintroduce) — [APP_CONTRACT.md:103, 134](docs/APP_CONTRACT.md). That ban was premised on response-shape ambiguity, which the conformance loop removes.
- **Design constraint.** The conformance suite must *never* test negative or security paths, such as "userB gets 403" or "phone hidden from others". Testing them would force the defense and erase the participant lever (`APP_CONTRACT.md §6`: "보안 방어 자체는 언급하지 않는다", security defenses themselves are not mentioned — [APP_CONTRACT.md:182](docs/APP_CONTRACT.md)). The marker approach still works for negatives, because the probe checks for the *presence of the positive marker* in the attacker's response.
- **Rate limiting.** The contract can pin a *signal convention* ("if you throttle, respond 429") without requiring throttling. That removes the keyword list.
- **What survives a perfect contract:**
  - the static presence regexes. They should be replaced by dynamic probes where possible. For example, CSRF can be tested dynamically by POSTing without a token, with an `Origin: evil` header and the session cookie. The PoC template for this already exists — [poc.py:151-183](grader/submissions/poc.py) — while scoring still uses the static regex.
  - CVE/typosquat ecosystem binding.
  - error-signature lists.
  - the session-forgery mechanism.
- **Dependency on the contract:** the only check whose FP/FN depends on the contract *and* the framework is `session_forgery`. Which signer is used and which session key holds the user id are contract-pinnable only if the prompt dictates session internals. For Flask/FastAPI that is cheap (`session["user_id"]`).

### Gaps
- No data on how often each heuristic fires today (skip rates). The current results database was not inspected.

---

## Q3. Rough porting effort per candidate (S/M/L)

### Takeaway
Staying on Flask, plus a contract and conformance loop, is S. FastAPI is the cheapest real switch (S–M): Python stays, the pip/osv pipeline is unchanged, and Starlette sessions are also itsdangerous-signed. Django is M; its built-in CSRF clashes with the grader's CSRF sender. Express is M–L. NestJS, Next.js, Spring Boot, Rails and Laravel are L, because of a new language plus build/boot cost and framework secure defaults. Go is M–L.

### Cited Findings
- Code that must change per language is concentrated in about 540 lines of static regex logic across A01/A02/A04/A05/A08/A09. File sizes: A01 320, A02 116, A04 334, A05_sql 259, A05_xss 339, A08 194, A09 33 (`wc -l scoring/checks/*.py`).
- The A03 CVE module is 492 lines. Its osv parse and severity logic is ecosystem-neutral; the parsing and `pip freeze` parts are not.
- The sandbox is three small files: Dockerfile 22, entrypoint 37, sitecustomize 23 lines (`wc -l`).
- Boot and resource limits: 45 s boot timeout, 512 MB memory, 1 CPU, 256 PIDs, 128 MB tmpfs `/work` — [config/scoring.yaml:113, 119-128](config/scoring.yaml), [scoring/shared/sandbox.py:79](scoring/shared/sandbox.py). Generation is capped at 600 s — [scoring.yaml:111](config/scoring.yaml).
- osv-scanner supports `package-lock.json`, `yarn.lock` and `pnpm-lock.yaml` (and installed `node_modules`), `go.mod` (and Go binaries), Maven `pom.xml` (transitive), Gradle lockfiles, `Gemfile.lock`, `composer.lock`, and Python `requirements.txt`/`poetry.lock`/`uv.lock` (and installed wheels) — [osv-scanner supported lockfiles](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/).
- Starlette `SessionMiddleware` signs a base64 JSON session with `itsdangerous.TimestampSigner`. Defaults: cookie `session`, `same_site=lax`, `https_only=False`, HttpOnly always on — [starlette/middleware/sessions.py](https://raw.githubusercontent.com/encode/starlette/master/starlette/middleware/sessions.py).
- Django's default session backend is the database; `signed_cookies` is opt-in via `SESSION_ENGINE`. A known `SECRET_KEY` with signed-cookie sessions plus the pickle serializer escalates to RCE — [Django sessions docs](https://docs.djangoproject.com/en/5.1/topics/http/sessions/).
- Express officially deprecated `csurf` (May 2025) and ships no built-in CSRF replacement — [Express blog 2025-05-16](https://expressjs.com/2025/05/16/express-cleanup-legacy-packages.html). Veracode reports csurf's double-submit mode is bypassable — [Veracode](https://www.veracode.com/blog/research/analysis-and-remediation-guidance-csrf-vulnerability-csurf-expressjs-middleware).
- Laravel's `ValidateCsrfToken` is in the `web` middleware group by default. It accepts `_token`, `X-CSRF-TOKEN` and `X-XSRF-TOKEN` — [Laravel 11 CSRF docs](https://laravel.com/docs/11.x/csrf).
- Spring Security enables CSRF by default for unsafe methods. It accepts header `X-CSRF-TOKEN`/`X-XSRF-TOKEN` or parameter `_csrf` — [Spring Security CSRF docs](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html).
- Rails: `default_protect_from_forgery` is enabled when Rails 5.2+ defaults are loaded, raising on an invalid token; GET is not checked — [Rails 5.2 API](https://api.rubyonrails.org/v5.2/classes/ActionController/RequestForgeryProtection.html), [CodeQL note](https://codeql.github.com/codeql-query-help/ruby/rb-csrf-protection-disabled/).
- Next.js Server Actions are POST-only and compare `Origin` with `Host`. Custom Route Handlers (`route.ts`) need manual CSRF protection. In production, server errors reach the client only as a hash — [Next.js security blog](https://nextjs.org/blog/security-nextjs-server-components-actions).
- Grader CSRF sender: field `csrf_token`, header `X-CSRF-Token`. It recognizes the names `_csrf|csrf_token|csrfmiddlewaretoken|authenticity_token` and meta `csrf-token` — [scoring/shared/csrf.py:21-34, 75-87](scoring/shared/csrf.py).

### Inferences (per framework; "LOC" = rough lines changed or added)

| Candidate | Sandbox / entrypoint / binding | Harvest globs | Static checks (~540 LOC of regex) | CVE / typosquat source | session_forgery / debug / verbose_errors / PoC | Prompt | Effort |
|---|---|---|---|---|---|---|---|
| **Flask (stay)** | none | none | keep; optionally replace CSRF/headers/cookies with dynamic probes | none | none | add exact response markers (ids, `/me`, admin marker, HTML for pages) plus conformance self-test | **S** (conformance suite ~300–600 LOC + prompt) |
| **FastAPI** | uvicorn defaults to 127.0.0.1 *(general knowledge, unverified)* → entrypoint `uvicorn main:app --host 0.0.0.0 --port 5000`, or a sitecustomize patch of `uvicorn.run` (~20 LOC) | add `main.py`, routers, `templates/**` | ~30–40% reusable as-is (SECRET_KEY, execute(), hashing, pickle, logging, `debug=True` regex matches `FastAPI(debug=True)`); replace Flask markers (flask_wtf, SESSION_COOKIE_*, after_request/Talisman, render_template_string, template_filter) with Starlette equivalents (`SessionMiddleware(... same_site/https_only)`, middleware headers, `Jinja2Templates`) → ~150–250 LOC | unchanged (pip/osv/PyPI) | forgery: swap to `TimestampSigner` (~30 LOC), payload key contract-pinned. Debug: no Werkzeug console → `debug_true` critical −20 "RCE" is no longer true; downgrade it. verbose_errors: Starlette debug traceback is Python, so most signatures still apply *(inference)* | rewrite Flask-specific lines (`app.run`, Flask 3.x API list, "Flask session") | **S–M** |
| **Django** | `manage.py migrate && runserver 0.0.0.0:5000` (or gunicorn); runserver default 127.0.0.1 *(general knowledge, unverified)*; DB-file deletion logic still fine | `manage.py`, `*/settings.py`, `*/urls.py`, `*/views.py`, `*/templates/**`, `*/migrations/**` (multi-dir) | names partly shared (`SESSION_COOKIE_HTTPONLY/SECURE/SAMESITE`, `DEBUG = True`, `SECRET_KEY`); new: MIDDLEWARE list (CsrfViewMiddleware, SecurityMiddleware, XFrameOptions), `@csrf_exempt`, `mark_safe`, `{% autoescape off %}`, `.raw()`/`.extra()`/`cursor.execute` → ~200–300 LOC | unchanged (pip) | **csrf.py must change**: Django expects form field `csrfmiddlewaretoken` / header `X-CSRFToken` *(general knowledge, unverified)*, but the grader sends `csrf_token` / `X-CSRF-Token` → every POST 403 → functional gate fails for every CSRF-protected app (~20 LOC fix: send several field/header names). Forgery: default DB sessions → not forgeable; only `signed_cookies` is → mostly `_undecidable`. Contract collision: Django `contrib.admin` mounts at `/admin` by convention | moderate rewrite | **M** |
| **Express.js** | `node:20-slim`; `npm ci`/`npm install`; `node app.js`; `app.listen(PORT)` without a host binds all interfaces *(general knowledge, unverified)* → just pass PORT env; must decide `NODE_ENV` (Express's default handler shows stacks outside production *(general knowledge, unverified)*), which is a grader-imposed choice | `package.json`, `package-lock.json`, `*.js`, `views/**`, `public/**` | full JS rewrite: `db.run/all` with template literals, EJS `<%-` / Handlebars `{{{` / Pug `!=` bypasses, helmet, express-session/cookie-session options, bcrypt/argon2, `eval`/`vm`/`node-serialize`, winston/pino → ~500–700 LOC, or lean on semgrep JS rules | osv on `package-lock.json` (supported) + `npm ls --all --json` in container for resolved versions; npm popular list + npm name rules; registry.npmjs.org for hallucination → ~150 LOC | forgery depends on library: express-session (server store, not forgeable), cookie-session (keygrip HMAC), JWT HS256 → the contract must pin one, else undecidable. No debug console equivalent → drop the `debug_true` critical. verbose_errors needs Node stack signatures (`at Layer.handle`, `node_modules/express`) | full rewrite | **M–L** |
| **NestJS** | as Express plus a TS build (`nest build`/`tsc`) inside the boot window | `src/**/*.ts`, `nest-cli.json`, `tsconfig*.json` | TS rewrite; decorator/DI indirection hurts regex further (e.g. `ValidationPipe({whitelist})` matters for mass-assignment) → ~600–800 LOC | npm (larger transitive tree → more CVE findings not chosen by the participant) | as Express | full rewrite | **L** |
| **Next.js** | `next build && next start` (build within 45 s / 512 MB is doubtful *(inference)*) or `next dev` (dev-mode errors leak by design — [Next.js blog](https://nextjs.org/blog/security-nextjs-server-components-actions)) | `app/**`, `pages/**`, `next.config.*`, `package*.json` | TSX rewrite; XSS reduces to `dangerouslySetInnerHTML`; CSRF to route.ts vs Server Actions | npm (very large tree) | Server Actions endpoints are hashed ids, not REST paths → the contract must force Route Handlers for every endpoint. Forgery: next-auth/iron-session/JWT, library-dependent | full rewrite | **L** |
| **Go (Gin / net/http)** | `golang` build stage + `go build` (module download needs network; time) then run the binary; `":5000"` binds all, but a literal `localhost:` must be forbidden in the contract | `go.mod`, `go.sum`, `*.go`, `templates/**` | Go rewrite: `fmt.Sprintf` into `db.Query`, `template.HTML(...)` bypass, `text/template` misuse, bcrypt pkg, gorilla/csrf, securecookie → ~400–600 LOC | osv `go.mod` + `go version -m` on the binary (supported); typosquatting is near-meaningless for URL-style module paths | gorilla/sessions securecookie or JWT → library-pinned forgery. No stack traces by default (Gin recovery) *(general knowledge, unverified)* → verbose_errors near-constant pass | full rewrite | **M–L** |
| **Spring Boot** | JDK image; Maven/Gradle build likely takes minutes and needs >512 MB *(inference)* → boot timeout and memory config must change | `pom.xml`/`build.gradle`, `src/main/java/**`, `src/main/resources/**` | Java rewrite; Spring Security config DSL (`csrf().disable()`, `headers()`), `JdbcTemplate` string concat, Thymeleaf `th:utext` | osv `pom.xml` (transitive supported) | JSESSIONID server-side → forgery N/A; whitelabel error page | full rewrite | **L** |
| **Rails** | Ruby image + `bundle install` (native gems such as sqlite3 compile) + `rails db:prepare` + `rails s -b 0.0.0.0`; dev vs prod env choice changes error pages and the need for `secret_key_base` | `Gemfile*`, `app/**`, `config/**`, `db/**` | Ruby rewrite: `where("...#{}")`, `html_safe`/`raw`, `skip_forgery_protection`, `has_secure_password` | osv `Gemfile.lock` (supported) | cookie store is encrypted with `secret_key_base`; forging needs Rails key derivation (portable but non-trivial) | full rewrite | **L** |
| **Laravel** | PHP + composer; `php artisan serve --host=0.0.0.0`; **APP_KEY is required**, which conflicts with the prompt rule that the app boots with no env (`default_prompt.md:21-28`) → entrypoint must `key:generate` | `composer.*`, `app/**`, `routes/**`, `resources/views/**`, `database/**`, `.env.example` | PHP rewrite: `DB::raw`/`whereRaw` concat, Blade `{!! !!}`, `$except` in CSRF, `APP_DEBUG` | osv `composer.lock` (supported) | grader regex misses the hidden `_token` field; it finds meta `csrf-token` only if the layout includes it → risk of 419 on all POSTs. Forgery: APP_KEY-encrypted cookie (not plain signing) | full rewrite | **L** |

Common to every non-Flask option:
- new sample fixtures (`samples/secure_board`, `samples/vulnerable_board`) and static-check tests;
- generation self-test instructions in the prompt (currently uv/venv-specific, [default_prompt.md:117-130](config/default_prompt.md));
- `Sandbox.__enter__` entry-file check ([sandbox.py:51-55](scoring/shared/sandbox.py));
- the `DATABASE=/work/app.db` env convention ([sandbox.py:77](scoring/shared/sandbox.py)).

### Gaps
- I did not measure real build and boot times for Spring, Next.js, Rails or NestJS under the 512 MB / 1 CPU / 45 s limits. The "doubtful" judgements are inferences.
- I did not verify current bind-address defaults for uvicorn, `runserver`, `next start`, `rails s` or `artisan serve` this session.
- I did not verify Django's exact CSRF header and field names this session. I am confident they differ from what `csrf.py` sends, but confirm before relying on it.

---

## Q4. Checks that become impossible, or pass trivially, in a given framework

### Takeaway
Frameworks with strong secure defaults (Django, Rails, Laravel, Spring + Security, Next.js) collapse several of the highest-weighted checks into near-constants. Affected: `csrf_protection` (weight 12, critical −6), `xss_template`, `stored_xss`/`reflected_xss`, `password_hashing`, part of `security_headers`. Those checks then no longer separate good prompts from bad ones. That is low variance rather than FP, and it hurts a contest. Frameworks with no defaults (Flask, FastAPI, Express, Go net/http) keep these as real participant levers. JSON-first frameworks make the XSS probes vacuous unless the contract mandates HTML pages.

### Cited Findings
- The current rubric already treats autoescape as "framework DEFAULT (free)" and adds CSP so that "an autoescape-only app can no longer earn a perfect XSS" — [config/scoring.yaml:27-31](config/scoring.yaml), [A05_injection_xss.py:164-166](scoring/checks/A05_injection_xss.py).
- The memory note on rubric calibration says weights were tuned so a framework-default baseline scores 10–30, favoring active hardening ([MEMORY.md](/Users/nekonic/.claude/projects/-Users-nekonic-Documents-GitHub-vibe-security-score/memory/MEMORY.md), entry "Rubric calibration"). A secure-by-default framework breaks this calibration.
- XSS probes skip non-HTML responses and credit them as passed — [A05_injection_xss.py:213-214, 290-292, 303-304](scoring/checks/A05_injection_xss.py).
- Next.js: Server Actions compare Origin with Host (CSRF effectively blocked), while route.ts needs manual CSRF. Production errors are hashed — [Next.js security blog](https://nextjs.org/blog/security-nextjs-server-components-actions).
- Laravel CSRF is on by default in the web group — [Laravel docs](https://laravel.com/docs/11.x/csrf). Spring Security CSRF is on by default — [Spring docs](https://docs.spring.io/spring-security/reference/servlet/exploits/csrf.html). Rails 5.2+ defaults enable forgery protection — [Rails API](https://api.rubyonrails.org/v5.2/classes/ActionController/RequestForgeryProtection.html).
- Express has no built-in CSRF (csurf deprecated) — [Express blog](https://expressjs.com/2025/05/16/express-cleanup-legacy-packages.html).
- Starlette sessions default to `SameSite=Lax` (which blocks classic cross-site form POSTs) and HttpOnly always on — [starlette sessions.py](https://raw.githubusercontent.com/encode/starlette/master/starlette/middleware/sessions.py). The current static `csrf_protection` check already accepts SameSite=Lax as a defense — [A01:37-42](scoring/checks/A01_broken_access_control.py). A FastAPI app using `SessionMiddleware` would therefore get CSRF credit by default if the check were ported literally.
- Django default sessions are DB-backed, so cookie forgery with SECRET_KEY is not applicable unless `signed_cookies` is chosen — [Django docs](https://docs.djangoproject.com/en/5.1/topics/http/sessions/).
- `debug_true` is critical −20 only because Werkzeug's debugger = RCE ([scoring.yaml:68, 78](config/scoring.yaml)). The PoC proves it through `__debugger__` ([poc.py:185-221](grader/submissions/poc.py)).

### Inferences
- **Django:** `csrf_protection` passes almost always (CsrfViewMiddleware is in the default settings), as do `xss_template` (autoescape), `password_hashing` (auth hashers), `sql_parameterization` (ORM), and X-Frame-Options/nosniff via default middleware *(general knowledge, unverified)*. `session_forgery` is mostly impossible (DB sessions). `debug_true` leaks a lot but has no RCE console, so the −20 "RCE" label is wrong. The DEBUG page would trip `verbose_errors`. Net: very low discrimination on about 30 rubric points.
- **Rails / Laravel / Spring Boot + Security:** the same collapse for CSRF, template escaping and hashing. Forgery: Spring has server-side JSESSIONID, so it is N/A. Rails/Laravel cookies are encrypted with key derivation, so forging is possible but the PoC must be re-engineered.
- **Next.js:** React escaping makes stored/reflected XSS pass unless `dangerouslySetInnerHTML` is used. CSRF depends on whether the contract forces route.ts; it must, for REST paths, and route.ts has no protection, so CSRF stays a lever. `verbose_errors` depends entirely on dev vs prod mode, which the grader imposes.
- **Go html/template:** contextual autoescaping makes XSS rare unless `template.HTML` is used. `verbose_errors` almost always passes. CSRF, headers, cookies and hashing remain real levers.
- **Express:** CSRF, headers (no helmet), cookie flags and rate limiting are all real levers, which is good for variance. But XSS depends on which template engine Codex picks (EJS `<%=` escapes, `<%-` doesn't). Static checks must handle several engines, or the contract pins one. `verbose_errors` becomes a near-constant fail unless the sandbox sets `NODE_ENV=production`. That is grader-imposed, and the repo's "never penalize a grader-imposed constraint" principle (memory "Scoring: minimize false positives"; [scoring.yaml:434-435](config/scoring.yaml)) suggests the sandbox should set production mode.
- **FastAPI / Express APIs / NestJS / Spring REST:** if the contract lets pages be JSON, `stored_xss` and `reflected_xss` (9 of 21 XSS weight) and `unrestricted_upload` (which checks served `text/html`) silently pass. The contract plus conformance must require `text/html` for `GET /posts`, `/posts/<id>`, `/search` and `/users/<id>`. This also matters for Flask today, since the current prompt does not state it explicitly.
- **Flask (current) and FastAPI keep the most levers.** No CSRF by default, SameSite on Flask defaults to None *(general knowledge, unverified)*, no default security headers, and Jinja autoescape on, which is why CSP was added. Flask additionally has the unique, verifiable Werkzeug-RCE critical. On grading-accuracy grounds alone, the evidence in this repo favors staying on Flask, or moving to FastAPI, and investing in the contract plus conformance loop and in dynamic replacements for the static presence checks, rather than switching to a batteries-included framework.

### Gaps
- No measurement of how often Codex-generated apps in each framework actually override the defaults (e.g. `@csrf_exempt`, `|safe`, `dangerouslySetInnerHTML`). Variance per framework is therefore inferred, not observed.
- I did not verify Flask's default `SESSION_COOKIE_SAMESITE` (None) or Express's default error-handler behavior this session.
