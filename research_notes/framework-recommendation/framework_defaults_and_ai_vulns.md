# Web framework security defaults vs. characteristic AI-assistant vulnerabilities (for an AI-generated-app security grader)

Scope note: notes are current as of 2026-10-24. Versions checked in this session: Flask 3.1.x docs, Django 6.1 docs, Spring Boot 4.1.2 / Spring Security 7.1.2 docs, Laravel 12.x docs (13.x is current), Next.js 14/15/16 serverActions docs, Go 1.25 `net/http`, Express 4.22 / 5.x, Hono >= 4.6.5, Rails 8 guide, PHP 8.4 manual.

Labels used below:
- **[V]** = verified against a source fetched or searched in this session (citation inline).
- **[GK]** = from the researcher's general knowledge of the framework, NOT re-verified in this session. The report writer should treat [GK] items as "probably correct, cite carefully". Every [GK] item is also listed under Gaps.

---

## Defaults matrix: which protections are ON by default vs must be added

### Takeaway
Django, Rails, Laravel and Spring Boot + Spring Security ship CSRF, template escaping, a parameterized ORM, a password-hashing helper and hardened session cookies **on by default**. Flask, FastAPI, Express, Fastify/Hono, Go and plain PHP ship almost none of these; each one becomes a separate decision for the app author (or the AI). Next.js sits in the middle: Server Actions get an Origin check and JSX escaping, but sessions, headers, DB access, rate limiting and authorization are all left to the author.

### Cited Findings

Legend for the matrix: **ON** = active in a default scaffold; **OPT** = shipped in the framework but you must call or enable it; **ADD** = third-party package or hand-written; **—** = not applicable.

| Protection | Flask 3.1 | FastAPI (Starlette) | Django 6.1 | Express 5 | NestJS | Fastify / Hono | Next.js 15/16 | Go net/http (1.25) / Gin | Spring Boot 4 + Security 7 | Rails 8 | Laravel 12 | Plain PHP 8.4 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| CSRF | ADD (Flask-WTF) [GK] | ADD; Starlette has no built-in CSRF middleware [V] | **ON** (CsrfViewMiddleware) [V] | ADD [GK] | ADD [GK] | Fastify ADD [GK]; Hono **OPT** Origin-check `csrf()` [V] | **ON for Server Actions** (Origin vs Host); route handlers ADD [V]/[GK] | **OPT** `http.CrossOriginProtection` (1.25+) [V]; Gin ADD [GK] | **ON** when spring-security is on the classpath [GK] | **ON** in new apps [V] | **ON** (`ValidateCsrfToken` in `web` group) [V] | ADD [GK] |
| Template autoescape | ON for .html via Jinja `render_template`; `render_template_string`/f-strings bypass it [GK] | ON if Jinja2Templates is used; JSON APIs n/a [GK] | **ON** [V] | Depends on engine (EJS `<%=` escapes, `<%-` raw; `res.send` template strings: none) [GK] | same as Express [GK] | Hono JSX escapes [GK] | **ON** (React JSX), `dangerouslySetInnerHTML` bypass [GK] | `html/template` contextual escaping ON; `text/template` none [GK] | Thymeleaf `th:text` ON, `th:utext` raw [GK] | ON (ERB) [GK]; guide only documents `h()` helpers [V] | ON (Blade `{{ }}`); `{!! !!}` raw [V] | none (`echo`) [GK] |
| Parameterized queries | none built in (raw `sqlite3` or SQLAlchemy optional) [GK] | none built in [GK] | **ON** (ORM); `raw()`/`extra()`/`RawSQL` warned [V] | none built in [GK] | depends on TypeORM/Prisma [GK] | none built in [GK] | none built in (Prisma/Drizzle optional) [GK] | `database/sql` placeholders OPT [GK] | JPA ON; string-built `@Query`/JDBC not [GK] | **ON** for hash conditions; `where("...#{}")`, `find_by_sql` not [V] | Eloquent/QB ON; `DB::raw`, `whereRaw` not [GK] | PDO prepared OPT [GK] |
| Password hashing helper | OPT (`werkzeug.security`) [GK] | ADD (passlib/pwdlib) [GK] | **ON** (auth framework, PBKDF2) [GK] | ADD (bcrypt) [GK] | ADD [GK] | ADD [GK] | ADD [GK] | ADD (`x/crypto/bcrypt`) [GK] | OPT (`PasswordEncoder`) [GK] | OPT `has_secure_password`; Rails 8 auth generator emits it [V] | **ON** (`Hash::make`) [GK] | OPT (`password_hash`) [GK] |
| Session cookie HttpOnly | **ON** [V] | **ON** (always) [V] | **ON** [GK] | express-session ON [GK] | — | plugin-dependent [GK] | no built-in session [GK] | manual `http.Cookie`; zero value = off [GK] | JSESSIONID ON [GK] | encrypted cookie store [V]; flag not documented in guide [V] | ON [GK] | **OFF** (`session.cookie_httponly=0`) [V] |
| Session cookie Secure | OFF [V] | OFF (`https_only=False`) [V] | OFF, must set `SESSION_COOKIE_SECURE` [V] | OFF [GK] | — | — | — | OFF [GK] | OFF over HTTP [GK] | not documented [V] | OFF [GK] | **OFF** [V] |
| Session cookie SameSite | **None** (unset) [V] | **Lax** [V] | Lax [GK] | unset [GK] | — | — | — | unset [GK] | unset [GK] | Lax [GK] | Lax [GK] | **unset** (`""`) [V] |
| Session data storage | signed client cookie (readable) [GK] | signed cookie, "readable but not modifiable" [V] | server-side DB [GK] | in-memory by default, "not designed for a production environment" [V] | — | — | — | — | server-side [GK] | **encrypted** cookie [V] | encrypted cookies [GK] | server files [GK] |
| Session secret handling | `SECRET_KEY` default **None** (sessions fail until set, so AI hardcodes one) [V] | `secret_key` is a required param [GK] | random key written into settings.py by `startproject` (`django-insecure-` prefix) [GK] | `secret` required; docs example is the literal `'s3Cur3'` [V] | — | — | — | — | — | `secret_key_base` in encrypted credentials [GK] | `APP_KEY` generated by installer [GK] | n/a (server-side IDs) |
| Security headers | ADD (Talisman) [GK] | ADD [GK] | **ON**: X-Frame-Options, nosniff, Referrer-Policy, COOP; HSTS/SSL redirect/CSP off [V] | ADD (helmet); `X-Powered-By: Express` ON [V] | ADD [GK] | Hono `secureHeaders()` OPT [V]; Fastify ADD [GK] | none; `X-Powered-By: Next.js` [GK] | ADD [GK] | **ON**: Cache-Control no-store, nosniff, HSTS (HTTPS only), XFO DENY, X-XSS-Protection 0 [V] | **ON**: XFO SAMEORIGIN, nosniff, X-XSS-Protection 0, X-Permitted-Cross-Domain-Policies, Referrer-Policy [V] | none [GK] | none; `X-Powered-By: PHP/x` [GK] |
| Rate limiting | ADD (Flask-Limiter) [GK] | ADD (slowapi) [GK] | **none**: "Django does not throttle requests to authenticate users" [V] | ADD; docs suggest rate-limiter-flexible [V] | ADD (`@nestjs/throttler`) [GK] | ADD [GK] | ADD [GK] | ADD [GK] | ADD [GK] | OPT `rate_limit`; auth generator adds `rate_limit to: 10, within: 3.minutes` on login [V] | OPT `throttle` middleware [GK] | ADD |
| Debug/error page exposure | `DEBUG` default False, but `app.run(debug=True)` gives the Werkzeug console, an RCE risk [V] | `debug=True` shows a traceback; `/docs` and `/openapi.json` on by default [GK] | `startproject` writes `DEBUG = True` [GK] | default handler shows stack traces when NODE_ENV≠production [GK]; default 404/error messages [V] | — | — | dev overlay only under `next dev` [GK] | none; `/debug/pprof` if imported [GK] | Whitelabel page; actuator exposes only `health` by default, env values sanitized [V] | dev-only exception page [GK] | `APP_DEBUG=true` in `.env.example` gives Ignition / error page [GK]; CVE-2021-3129 [V] | `display_errors` per php.ini [GK] |
| Upload handling | `MAX_CONTENT_LENGTH` None; `MAX_FORM_MEMORY_SIZE` 500 000; `MAX_FORM_PARTS` 1000 [V]; `secure_filename` OPT [GK] | needs python-multipart; no size limit [GK] | File/ImageField; Pillow validation "not bulletproof"; serve uploads from a separate domain [V] | ADD (multer) [GK] | ADD [GK] | plugin [GK] | ADD [GK] | `MaxBytesReader` OPT [GK] | multipart limits ON (1MB file) [GK] | Active Storage [GK] | `store()` gives random names [GK] | `move_uploaded_file`; `.php` upload means RCE [GK] |
| Mass assignment | n/a unless `Model(**request.form)` [GK] | Pydantic models whitelist fields (partial) [GK] | ModelForm requires `fields`/`exclude` [GK] | **none** (`Object.assign(user, req.body)`; prototype pollution) [GK] | `ValidationPipe({whitelist:true})` OPT [GK] | Fastify JSON-schema OPT [GK] | **none** (`prisma.update({data: body})`) [GK] | struct decode binds all exported fields [GK] | `@ModelAttribute` binds all setters [GK] | **ON** strong params (`permit`) [GK]; guide shows `params.permit` [V] | **ON** (`$fillable`/`$guarded`; avoid `$request->all()`) [V] | n/a |
| SSRF protection | none in any framework; always ADD [GK] | none | none | none | none | none | none (`next/image` `remotePatterns` covers only the image optimizer) [GK] | none | none | none | none | none; `file_get_contents` accepts `file://` and `php://` [GK] |
| Host header validation | `TRUSTED_HOSTS` default None (3.1+) [V] | TrustedHostMiddleware OPT [V] | **ON** (`ALLOWED_HOSTS`) [V] | none [GK] | none | none | — | none | — | dev-only host authorization [V] | — | none |

Supporting citations for the [V] cells:
- Flask: `SESSION_COOKIE_HTTPONLY` True, `SESSION_COOKIE_SECURE` False, `SESSION_COOKIE_SAMESITE` None, `SECRET_KEY` None, `DEBUG` False, `MAX_CONTENT_LENGTH` None, `MAX_FORM_MEMORY_SIZE` 500_000, `MAX_FORM_PARTS` 1_000, `TRUSTED_HOSTS` None (added 3.1), `PERMANENT_SESSION_LIFETIME` 31 days — [Flask 3.1 config docs](https://flask.palletsprojects.com/en/stable/config/)
- Werkzeug debugger: if debug is active, `/console` can give RCE; the PIN is derived from guessable values and machine-id/MAC, so any file-read bug lets an attacker recompute it — [HackTricks: Werkzeug](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug)
- Starlette SessionMiddleware: cookie `session`, max_age 2 weeks, `same_site='lax'`, `https_only=False`, always HttpOnly, "readable but not modifiable"; no built-in CSRF (third-party asgi-csrf / starlette-csrf) — [Starlette middleware docs (GitHub source)](https://raw.githubusercontent.com/encode/starlette/master/docs/middleware.md)
- Django 6.1: autoescaping, parameterized querysets, CSRF middleware "providing you have enabled and used it", X-Frame-Options middleware, ALLOWED_HOSTS validation, SSL/HSTS/secure cookies must be configured, CSP config new in 6.0, "Django does not throttle requests to authenticate users", upload caveats (PNG+HTML polyglot passes Pillow; serve from a separate domain) — [Django security topic](https://docs.djangoproject.com/en/stable/topics/security/)
- Express: Helmet recommended; Express sends `X-Powered-By` by default; default 404/error messages exposed unless custom handlers are added; express-session in-memory store "not designed for a production environment"; don't use the default session cookie name; brute-force blocking via rate-limiter-flexible. The page says nothing about CSRF or the query parser — [Express security best practices](https://expressjs.com/en/advanced/best-practice-security.html)
- Express 5 changed the default query parser from `extended` (qs) to `simple`. CVE-2024-51999 (extended-mode `req.query` prototype) was later rejected; Express 4.22.2 set `arrayLimit: 1000` — [Express History.md mirror](https://premierleague.rrkabel.com/node_modules/express/History.md); [expressjs/express#2661](https://github.com/expressjs/express/issues/2661)
- Next.js Server Actions: the Origin header host is compared with Host / X-Forwarded-Host and the action is rejected on mismatch; with no `allowedOrigins` only same origin is allowed. In 16.x docs, a request **without** an Origin header is let through with a warning — [Next.js serverActions config](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions); [Next.js 15 version](https://nextjs.org/docs/15/app/api-reference/config/next-config-js/serverActions). OWASP: Server Actions accept POSTs independently of the page that renders the form, so re-authorize on the server — [OWASP Next.js Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html)
- Go 1.25 `http.CrossOriginProtection`: uses Sec-Fetch-Site or Origin-vs-Host; safe methods pass; non-safe cross-origin requests get 403; requests with neither header are allowed; Sec-Fetch-Site is only sent for trustworthy (HTTPS) origins — [Alex Edwards: A modern approach to preventing CSRF in Go](https://alexedwards.net/blog/preventing-csrf-in-go); [Calhoun: CSRF protection via headers in Go 1.25](https://www.calhoun.io/csrf-protection-via-headers-in-go-125/); [net/http csrf.go source](https://go.googlesource.com/go/+/14596908b73c55d7e6cda830751b9a6c65dd2c10/src/net/http/csrf.go)
- Hono: `secureHeaders()` has "optimal settings by default" (Helmet-inspired) — [Hono Secure Headers](https://hono.dev/middleware/builtin/secure-headers). `csrf()` compares Origin with the request URL; it is not token-based and has caveats for old browsers and proxies — [Hono CSRF](https://hono.dev/middleware/builtin/csrf). Bypass advisories were fixed in 4.5.8 (uppercase MIME) and 4.6.5 (missing Content-Type) — [CVE-2024-43787 (Tenable)](https://tenable.com/cve/CVE-2024-43787); [CVE-2024-48913](https://db.fluidattacks.com/adv/npm/hono/CVE-2024-48913)
- Spring Security 7.1.2 default headers: `Cache-Control: no-cache, no-store, max-age=0, must-revalidate`, `Pragma: no-cache`, `Expires: 0`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security: max-age=31536000 ; includeSubDomains` (HTTPS only), `X-Frame-Options: DENY`, `X-XSS-Protection: 0` — [Spring Security headers](https://docs.spring.io/spring-security/reference/features/exploits/headers.html)
- Spring Boot 4.1.2 Actuator: "By default, only the health endpoint is exposed over HTTP and JMX"; `heapdump` is not exposed; `/env` values "always fully sanitized (replaced by ******)" by default — [Spring Boot actuator endpoints](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- Rails: `default_protect_from_forgery` is "the default for newly created Rails applications"; "Rails encrypts cookies by default"; the cookie store uses the encrypted jar (integrity plus confidentiality); default headers are XFO SAMEORIGIN, X-XSS-Protection 0, nosniff, X-Permitted-Cross-Domain-Policies none, Referrer-Policy strict-origin-when-cross-origin; HSTS only with `force_ssl`; `filter_parameters` defaults; rate limiting is per controller via `rate_limit`; host authorization is on by default only in development; AR finder methods escape automatically but `where("...")` fragments and `find_by_sql` do not — [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- Rails 8 `bin/rails generate authentication` creates User with `has_secure_password`, Session/Current models, and a SessionsController with `rate_limit to: 10, within: 3.minutes, only: :create` — [BigBinary: Rails 8 authentication generator](https://www.bigbinary.com/blog/rails-8-introduces-a-basic-authentication-generator)
- Laravel 12: `Illuminate\Foundation\Http\Middleware\ValidateCsrfToken` is "included in the web middleware group by default"; exclusions via `validateCsrfTokens(except: [...])`; encrypted `XSRF-TOKEN` cookie — [Laravel 12 CSRF docs](https://laravel.com/docs/12.x/csrf). Blade `{{ }}` escapes and `{!! !!}` is raw; use `$fillable`/`$guarded` and avoid `$request->all()` (secondary guide) — [Benjamin Crozat: Laravel security best practices](https://benjamincrozat.com/laravel-security-best-practices)
- Laravel Ignition CVE-2021-3129: unauthenticated RCE in Ignition < 2.5.2 via `file_get_contents`/`file_put_contents`, exploitable when debug mode is on with Laravel < 8.4.2; CVSS 9.8; CISA KEV (added 2023-09-18); exploitation is mostly broad automated scanning — [Vulert CVE-2021-3129](https://vulert.com/vuln-db/CVE-2021-3129); [Flare: improving Ignition's security](https://flareapp.io/blog/improving-ignitions-security); [CrowdSec CVE explorer](https://app.crowdsec.net/cti/cve-explorer/CVE-2021-3129)
- PHP 8.4 session defaults: `session.cookie_httponly "0"`, `session.cookie_secure "0"`, `session.cookie_samesite ""` (no attribute set), `session.use_strict_mode "0"`, `session.use_only_cookies "1"`, `session.name "PHPSESSID"` — [PHP manual: session configuration](https://www.php.net/manual/en/session.configuration.php)

### Inferences
- Counting matrix rows that are ON by default: Django, Rails, Laravel and Spring Security each get roughly 7 of 13 "for free". Flask and FastAPI get about 2–3 (HttpOnly, Jinja escaping, SameSite=Lax in Starlette). Express, Go and plain PHP get about 0–1. In plain PHP even HttpOnly is off.
- Flask is unusual among the "bare" frameworks: its cookie defaults (HttpOnly on, Secure off, SameSite **unset**) and `SECRET_KEY=None` force the AI to make explicit decisions about the secret and SameSite. Today's grader already exploits this (weak/hardcoded secret leads to session forgery).
- No framework does anything about SSRF. The link-preview feature is therefore framework-independent: a pure prompt-controlled lever in every candidate.

### Gaps
- All [GK] cells were not re-verified in this session. Most important to verify before relying on them: Django `startproject` writes `DEBUG = True` and a `django-insecure-` key; Laravel `.env.example` sets `APP_DEBUG=true`; Spring Security CSRF on by default in 7.x; express-session cookie defaults (`httpOnly: true`, `secure: false`, name `connect.sid`); Express's default error handler printing stack traces when `NODE_ENV` ≠ production; FastAPI `/docs` exposure; Next.js `X-Powered-By` header; Fastify plugin defaults (no Fastify search returned results).
- Could not fetch Fastify or NestJS official security docs. Their rows are [GK] only.
- Whether Django 6.x / Laravel 13 changed any default after the versions fetched was not checked.

---

## What AI assistants characteristically omit or get wrong, per framework (with evidence)

### Takeaway
Cross-framework studies agree: current agents mostly avoid SQLi and template XSS when the framework makes the safe path the default, but they consistently skip **security controls** (CSRF, rate limiting, headers, authorization depth) and **always** introduce SSRF when a URL-fetch feature exists. The prompt's wording changes outcomes substantially (about 2x fewer findings and zero Critical/High in one twin-prompt study), which is the variance a booth grader needs.

### Cited Findings
**Cross-framework studies**
- Veracode 2025 GenAI Code Security Report (80 tasks, 100+ LLMs): about 45% of samples introduced OWASP Top-10 flaws. Failure rate by language: Java 72%, C# 45%, JavaScript 43%, Python 38%. XSS (CWE-80) defenses failed in 86% of relevant samples, log injection (CWE-117) in 88% — [Veracode blog](https://veracode.com/blog/genai-code-security-report); [Veracode press release](https://www.veracode.com/press-release/ai-generated-code-poses-major-security-risks-in-nearly-half-of-all-development-tasks-veracode-research-reveals/)
- Tenzai (tests Dec 2025, published Jan 2026): Cursor, Claude Code, OpenAI Codex, Replit and Devin each built the same 3 apps (15 apps). Results: 69 vulnerabilities; "None of the generated apps contained an exploitable SQLi or XSS vulnerability"; improper API authorization was "one of the most common issues"; **all five agents introduced SSRF**; 4/5 allowed negative orders. Quote: "All the coding agents, across every test we performed, failed miserably when it came to security controls", and they "didn't even try" — [SecurityWeek](https://www.securityweek.com/vibe-coding-tested-ai-agents-nail-sqli-but-fail-miserably-on-security-controls/); [InfoWorld](https://www.infoworld.com/article/4116937/output-from-vibe-coding-tools-prone-to-critical-security-flaws-study-finds-2.html). Critical-rated flaws came only from Claude Code (4), Devin (1) and Codex (1) — [InfoWorld via search summary](https://www.infoworld.com/article/4116937/output-from-vibe-coding-tools-prone-to-critical-security-flaws-study-finds-2.html). A secondary site claims zero apps built CSRF protection, but SecurityWeek does not say this, so treat it as **unverified** — [awesomeagents.ai](https://awesomeagents.ai/news/vibe-coding-security-69-vulnerabilities/). Tenzai did not publish which frameworks the apps used.
- Andročec, "Vibe Coding and Web Application Security: A Twin-Prompt Study" (arXiv 2608.20963, Aug 2026, CECIIS 2026): 6 apps × 2 prompts (baseline vs. appended security-requirements section), one agent and model. Confirmed findings: **51 baseline vs. 24 security-aware**, fewer in every app, and **0 Critical/High** in the security-aware variant. The most severe remaining finding was caught only by manual testing. n=1 per variant, so descriptive only — [arXiv abstract](https://arxiv.org/abs/2608.20963)
- Perry et al. (Stanford), "Do Users Write More Insecure Code with AI Assistants?": 47 participants using codex-davinci-002 wrote significantly less secure code, with especially significant results for SQL injection and string encryption, and were *more* confident their code was secure — [The Register](https://www.theregister.com/2022/12/21/ai_assistants_bad_code); [arXiv 2211.03622 (archived)](https://webcf.waybackmachine.org/web/20221113074609/https://arxiv.org/pdf/2211.03622.pdf)
- Pearce et al., "Asleep at the Keyboard?": about 40% of Copilot programs across 89 scenarios had potentially exploitable vulnerabilities (Python, C, Verilog only) — [The Register](https://www.theregister.com/2022/12/21/ai_assistants_bad_code)

**Incidents tied to platform or framework defaults**
- Lovable / Supabase, CVE-2025-48757: insufficient Row-Level Security in Lovable-generated apps (through 2025-04-15) let unauthenticated attackers read or write arbitrary tables using only the public anon key. Scale: 170 of 1,645 showcase apps (~10%), 303 endpoints. CVSS 9.3 in most sources (one says 8.26). Responsibility is contested: platform default vs. user misconfiguration — [Superblocks](https://www.superblocks.com/blog/lovable-rls-breach); [Pluto Security](https://blog.pluto.security/p/cve-202548757-what-happened-why-it-b22); [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2025-48757/)
- Next.js CVE-2025-29927 (CVSS 9.1): the internal `x-middleware-subrequest` header was trusted from clients, so setting it skips middleware entirely. Affects self-hosted `next start` / standalone apps from 11.1.4 through 15.2.2; patched in 15.2.3, 14.2.25, 13.5.9 and 12.3.5; Vercel/Netlify/static exports not affected. Apps that do auth **only in middleware** are fully bypassed — [Snyk](https://snyk.io/blog/cve-2025-29927-authorization-bypass-in-next-js-middleware/); [Fastly](https://fastly.com/blog/cve-2025-29927-authorization-bypass-in-next-js); [UpGuard](https://upguard.com/blog/critical-middleware-bypass-vulnerability-in-next-js-cve-2025-29927). Version ranges differ slightly across sources (Azion lists 11.x as unpatched) — [Azion](https://www.azion.com/en/documentation/products/guides/secure/mitigate-cve-2025-29927-nextjs/)
- Express + Mongoose NoSQL injection: CVE-2026-42334 (CVSS 7.5) — `sanitizeFilter` did not recurse into `$nor`, so `$ne` etc. slipped through. Risky pattern: `Model.findOne(req.body)`. Fixed in 6.13.9 / 7.8.9 / 8.22.1 / 9.1.6 — [GitLab advisory](https://advisories.gitlab.com/npm/mongoose/CVE-2026-42334/); [OSV](https://osv.dev/vulnerability/CVE-2026-42334). Not relevant if the app is forced onto SQLite.
- Laravel Ignition CVE-2021-3129: shows that "debug left on" in Laravel escalates to unauthenticated RCE (KEV-listed) — [Vulert](https://vulert.com/vuln-db/CVE-2021-3129)

**Per-framework omission patterns** (evidence where available, otherwise inference marked [GK])
- **Flask / FastAPI (Python)**: Veracode puts Python at the lowest failure rate (38%) [Veracode, above]. The decisions an AI must make by hand are CSRF (no built-in), `SECRET_KEY` (default None means AI hardcodes a literal), SameSite (Flask default unset), `debug=True` in `app.run`, raw `sqlite3` f-string SQL, `render_template_string` SSTI, upload size/filename checks, rate limiting, and SSRF in requests-based link preview [Flask config docs; Werkzeug/HackTricks; Starlette docs above]. FastAPI-specific [GK]: Pydantic input models reused as ORM output (leaking `phone`/`password_hash`), `/docs` left public, JWT in localStorage instead of cookies.
- **Django**: the "free-pass" items are CSRF, escaping, ORM and hashing [Django docs]. What remains for the AI: `DEBUG` (scaffold True [GK]), `@csrf_exempt` sprinkled to fix 403s on fetch/AJAX [GK; Django docs warn "only when absolutely necessary"], `|safe`/`mark_safe` for rendered content [Django docs], `raw()`/`extra()` [Django docs], login throttling (none built in) [Django docs], SECURE_* flags [Django docs], IDOR on object views, upload served from same origin [Django docs].
- **Express / NestJS / Fastify (Node)**: Veracode JavaScript failure is 43% [Veracode]. Every control is opt-in. Express defaults leak `X-Powered-By` and default error messages [Express docs]; the docs' own session example uses the secret `'s3Cur3'` [Express docs], which AIs tend to copy as a hardcoded secret [inference]. Typical omissions [GK]: helmet, CSRF (`csurf` deprecated, so AI often skips it), rate limit, `Object.assign(user, req.body)` mass assignment / prototype pollution, `res.send(\`...${q}...\`)` reflected XSS, multer without type/size limits, `app.use(cors({origin: true, credentials: true}))`.
- **Next.js**: Server Actions have a built-in Origin check, but Route Handlers do not [Next.js docs; OWASP]. Characteristic risk: authorization only in `middleware.ts` (CVE-2025-29927 shows why that is fragile) [Snyk]. OWASP warns that Server Actions are callable independently of the rendering page, so a missing per-action authorization check means BOLA/IDOR [OWASP cheat sheet].
- **Go / Gin**: CSRF is now one line (`http.CrossOriginProtection`) but opt-in [Edwards]; cookies are manual structs. [GK]: AIs often write `fmt.Sprintf` SQL, forget `MaxBytesReader`, and use `text/template` or string concatenation for HTML.
- **Spring Boot**: Java has the highest AI failure rate (72%) [Veracode]. Spring Security, when included, turns on headers and CSRF [Spring docs; GK for CSRF]. [GK]: AI commonly writes `http.csrf(csrf -> csrf.disable())` to make POSTs work, and exposes actuator with `management.endpoints.web.exposure.include=*`. Both are single-line, statically detectable decisions.
- **Rails / Laravel**: most controls are ON [Rails guide; Laravel docs]. Remaining AI levers [GK]: `skip_forgery_protection` / CSRF `except`, `html_safe`/`raw` and `{!! !!}`, `params.permit!` / `$guarded = []`, `where("title LIKE '%#{q}%'")` / `whereRaw`, `APP_DEBUG=true`, missing per-record authorization.
- **Plain PHP**: nothing is ON, including HttpOnly [PHP manual]. AI output varies maximally, but much of it can be trivially broken (e.g., `.php` upload means RCE) [GK].

### Inferences
- The best-evidenced "AI reliably fails" classes are SSRF (5/5 agents, Tenzai), authorization/BOLA (Tenzai; Lovable RLS), missing security controls generally (Tenzai), and XSS in contexts where the framework does not escape by default (Veracode 86%). These are the classes where prompt wording should create the widest score spread.
- SQLi and template XSS are close to solved **when the framework's default path is safe** (Tenzai found zero). In a Flask + raw sqlite3 setup they remain live because the safe path (placeholders) is a choice. That explains why the current Flask grader still sees SQLi variance.
- The twin-prompt study gives direct evidence that "participant prompt → security score" is a real, sizable effect (51 → 24 findings), which supports the booth's premise regardless of framework.

### Gaps
- No study found that compares AI-generated **security outcomes across frameworks** with the same app spec (e.g., Flask vs. Django vs. Express). Veracode reports per **language**, not per framework. Tenzai did not disclose stacks.
- No primary evidence was found for "AI disables Spring CSRF" or "AI sprinkles `@csrf_exempt`". These are practitioner folklore [GK] and should be presented as hypotheses.
- Could not read the full Andročec PDF (binary not extractable here). Framework and vulnerability classes in that study are unknown.
- Tenzai's original report was not retrieved, only press coverage.

---

## Key Q1: Which frameworks give a "free pass" on many checks (low variance across AI outputs)?

### Takeaway
Django, Rails, Laravel and Spring Boot + Spring Security neutralize CSRF, template XSS, ORM SQLi, password hashing, HttpOnly/SameSite cookies, and (Rails/Spring/Django) baseline security headers by default. AI outputs in these frameworks will mostly tie on those checks unless the participant actively asks to weaken them.

### Cited Findings
- Django: CSRF, autoescape, parameterized querysets, X-Frame-Options, ALLOWED_HOSTS validation on by default — [Django docs](https://docs.djangoproject.com/en/stable/topics/security/)
- Rails: CSRF default in new apps, encrypted cookies, five default security headers, AR escaping for finders — [Rails Security Guide](https://guides.rubyonrails.org/security.html)
- Laravel: CSRF middleware in the `web` group by default — [Laravel 12 CSRF](https://laravel.com/docs/12.x/csrf); Blade escaping and mass-assignment guards — [Crozat](https://benjamincrozat.com/laravel-security-best-practices)
- Spring Security: seven default security headers — [Spring Security headers](https://docs.spring.io/spring-security/reference/features/exploits/headers.html); actuator only `health` by default — [Spring Boot actuator](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- When the safe path is the default, agents produced zero exploitable SQLi/XSS across 15 apps — [SecurityWeek/Tenzai](https://www.securityweek.com/vibe-coding-tested-ai-agents-nail-sqli-but-fail-miserably-on-security-controls/)

### Inferences
- In Django/Rails/Laravel the remaining variance collapses onto: DEBUG flag, rate limiting, SECURE_* / HTTPS flags (unobservable over plain HTTP in a sandbox), authorization (IDOR on profile/admin), SSRF, upload content-type/same-origin serving, and explicit opt-outs (`csrf_exempt`, `|safe`, `raw`). Roughly 5–6 independent levers vs. ~12 in Flask/Express. With the current rubric (CSRF, XSS, SQLi, cookie flags, headers each weighted), a Django baseline would likely score high, which conflicts with the rubric calibration goal of a framework-default baseline at 10–30.
- A secure-by-default framework also *raises* the floor: a careless prompt still gets CSRF/XSS/SQLi protection. That is good for real-world safety but bad for "your prompt matters" scoring.
- Spring Boot adds operational cost: JVM build/boot latency and Codex build reliability. It also has the worst AI failure rate per Veracode (Java 72%), but that variance is largely in code-level CWEs the static side catches, not in the default-on web protections.

### Gaps
- No empirical measurement of score variance per framework for the booth's specific app spec exists. It would need a pilot (e.g., N=10 Codex generations × 3 prompt styles × 3 frameworks).

---

## Key Q2: Which frameworks leave many independent, prompt-controllable security decisions (high variance = good scoring levers)?

### Takeaway
Flask, FastAPI, Express (and Fastify/Hono), Go net/http and plain PHP leave 10+ independent decisions to the author: CSRF, secret, SameSite/Secure, headers, rate limit, debug, upload limits, SQL style, HTML escaping style, mass-assignment, SSRF, authorization. Flask and Express are the sweet spot: wide variance, while the safe path is still reachable in one line each, so a good prompt can visibly win.

### Cited Findings
- Flask leaves SameSite unset, Secure off, `SECRET_KEY` None, no upload size limit, no host validation by default — [Flask config](https://flask.palletsprojects.com/en/stable/config/)
- Starlette/FastAPI: no built-in CSRF; secure-ish cookie defaults (Lax, HttpOnly) but `https_only=False` — [Starlette docs](https://raw.githubusercontent.com/encode/starlette/master/docs/middleware.md)
- Express: helmet, custom error handlers, cookie flags and brute-force protection are all recommendations, not defaults — [Express best practices](https://expressjs.com/en/advanced/best-practice-security.html)
- Go: CSRF protection exists since 1.25 but must be wrapped explicitly — [Alex Edwards](https://alexedwards.net/blog/preventing-csrf-in-go)
- PHP: session cookie HttpOnly/Secure/SameSite and strict mode all off by default — [PHP manual](https://www.php.net/manual/en/session.configuration.php)
- Adding a security-requirements section to the prompt halved confirmed findings and removed all Critical/High — [Andročec, arXiv 2608.20963](https://arxiv.org/abs/2608.20963)

### Inferences
- **Flask** (current) is a strong choice. It gives high variance on CSRF, SameSite, secret strength (session forgery is cleanly provable), debug console, SQL style (raw sqlite3), SSTI, upload, rate limiting, SSRF and authorization. Its few defaults (HttpOnly on, Jinja autoescape for `.html` templates) remove two noisy checks without flattening the field.
- **FastAPI** is slightly less variable than Flask: Lax/HttpOnly on by default, Pydantic narrows mass assignment. Codex tends to generate a JSON API + SPA for FastAPI [GK], which pushes XSS into the browser (harder to grade over HTTP; see Q3).
- **Express** has the most levers (even headers and `X-Powered-By` are opt-in), but the result is template-engine-dependent: EJS/Pug/Handlebars/raw `res.send` each have different escaping semantics. That multiplies the grader's static-analysis surface and FP risk.
- **Plain PHP** has maximal variance but a too-low floor (a single upload can lead to RCE of the sandbox) and a messy static-analysis target. Not recommended for fair booth scoring.
- **Next.js** has moderate variance, but its levers are mostly authorization and server-action design, which are hard to probe generically.

### Gaps
- No source quantifies how often Codex specifically picks each template engine or architecture (SSR vs. SPA) per framework. A pilot generation run would answer this.

---

## Key Q3: Which vuln classes are dangerous but hard to observe externally vs. cleanly observable over HTTP?

### Takeaway
Cleanly HTTP-observable (low FP/FN): reflected XSS in server-rendered HTML, SQLi, debug-page and console exposure, cookie flags, security headers, CSRF (cross-origin state change with a victim session), login rate limiting, IDOR on the profile phone number, mass-assignment privilege escalation, forged session with a guessable secret, SSRF with a canary listener, and upload content-type/served-as-HTML. Hard to observe: hashing algorithm, secret entropy, DOM/client-side XSS in SPAs, prototype pollution, blind SSRF without a canary, log injection, race conditions, and HTTPS-only settings (Secure/HSTS) when the sandbox runs plain HTTP.

### Cited Findings
- Next.js Server Actions accept POSTs independently of the rendering page; the CSRF check passes requests lacking an Origin header (with a warning) — [Next.js docs](https://nextjs.org/docs/app/api-reference/config/next-config-js/serverActions); [OWASP Next.js cheat sheet](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html)
- Go's CrossOriginProtection and the Sec-Fetch-Site header only apply on trustworthy (HTTPS) origins; requests without the headers pass. A grader sending raw HTTP requests must therefore craft Origin headers to test it — [Alex Edwards](https://alexedwards.net/blog/preventing-csrf-in-go)
- Django: HTTPS/HSTS/secure-cookie settings are explicit opt-ins that only take effect behind HTTPS — [Django docs](https://docs.djangoproject.com/en/stable/topics/security/)
- Spring Security HSTS is only emitted on HTTPS requests — [Spring Security headers](https://docs.spring.io/spring-security/reference/features/exploits/headers.html)
- Mongoose NoSQL injection depends on query-construction patterns (`findOne(req.body)`) — [GitLab advisory](https://advisories.gitlab.com/npm/mongoose/CVE-2026-42334/)
- The most severe finding in the twin-prompt study was detected **only by manual testing**, i.e., automated tooling missed it — [Andročec](https://arxiv.org/abs/2608.20963)
- SSRF was planted in Tenzai's spec and every agent fell for it. This is observable when the tester controls a target URL — [SecurityWeek](https://www.securityweek.com/vibe-coding-tested-ai-agents-nail-sqli-but-fail-miserably-on-security-controls/)

### Inferences
- **Framework effect on observability**:
  - Server-rendered frameworks (Flask/Jinja, Django, Rails, Laravel, Express+EJS) put reflected XSS in the HTTP response body, so a probe is deterministic.
  - SPA-style output (Next.js client components, FastAPI + React, NestJS API) moves XSS into the DOM, which needs a headless browser. That adds FN risk and latency.
  - Next.js Server Actions use hashed action IDs in a `Next-Action` header [GK], so generic CSRF/IDOR probes must discover the IDs first. This hurts black-box accuracy.
- **Secure flag / HSTS / Sec-Fetch-Site** are not meaningfully testable in an HTTP-only sandbox. Score them statically or not at all (consistent with the existing "don't penalize grader-imposed constraints" principle).
- **Password hashing** is invisible over HTTP, but the grader owns the SQLite file, so a DB inspection after signup (bcrypt `$2b$`, `pbkdf2:`/`scrypt:` Werkzeug prefixes, Django `pbkdf2_sha256$`) is deterministic. This works best in frameworks without a forced default (Flask/Express/FastAPI/Go). In Django/Laravel/Rails it is always "pass".
- **Prototype pollution / NoSQL injection** (Express-specific classes) are hard to prove generically and mostly irrelevant with SQLite. Choosing Express adds static-analysis rules without adding reliable dynamic probes.
- **Mass assignment** is cleanly observable (sign up with `is_admin=1` / `role=admin`, then request the admin page). It varies only in frameworks without strong-params/`$fillable` (Express, Flask+SQLAlchemy `**form`, Next.js+Prisma, Spring `@ModelAttribute`).

### Gaps
- No source measured FP/FN rates of black-box probes per framework. The observability ranking above is the researcher's analysis.
- Whether Codex-generated Next.js apps typically use Server Actions or Route Handlers is unknown without a pilot.

---

## Key Q4: Framework-specific "debug mode" / error-page signatures that are deterministic to detect

### Takeaway
Each framework's debug or error page has a stable textual fingerprint and often a fixed debug endpoint. These make cheap, near-zero-FP probes: trigger a 404/500 and string-match, and probe a fixed path. The highest-severity ones are the Werkzeug console (RCE), Laravel Ignition (CVE-2021-3129 RCE), and Spring Actuator `env`/`heapdump` when over-exposed.

### Cited Findings
- Werkzeug: `/console` reachable in debug mode can give RCE; PIN-protected but derivable from machine-id/MAC plus guessable values via any file read — [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/werkzeug); [Rezydev notes](https://rezydev.com/notes/web-hacking/framework-specific/python-flask/werkzeug-debug-console-pin-exploit-rce)
- Flask `DEBUG` default False; enabling it via `flask run --debug` turns on the interactive debugger — [Flask config](https://flask.palletsprojects.com/en/stable/config/)
- Laravel Ignition RCE (CVE-2021-3129) only when debug mode is on; KEV; CVSS 9.8; mass-scanned — [Vulert](https://vulert.com/vuln-db/CVE-2021-3129); [CrowdSec](https://app.crowdsec.net/cti/cve-explorer/CVE-2021-3129)
- Spring Boot Actuator: only `health` over HTTP by default; `heapdump` restricted; `env` sanitized as `******` by default — [Spring Boot docs](https://docs.spring.io/spring-boot/reference/actuator/endpoints.html)
- Express: `X-Powered-By: Express` by default, and default "Not Found" / error responses unless custom handlers are set — [Express best practices](https://expressjs.com/en/advanced/best-practice-security.html)
- Rails host authorization and the rich exception pages are development-environment behaviors — [Rails Security Guide](https://guides.rubyonrails.org/security.html)

Fingerprint strings and paths (all **[GK]**, to be validated against a live instance of each framework before use as probes):
- **Flask/Werkzeug debugger**: HTML title containing "Werkzeug Debugger"; body text "The debugger caught an exception in your WSGI application"; static resource `/?__debugger__=yes&cmd=resource&f=debugger.js`; `/console` page "Interactive Console" with a PIN prompt. Header `Server: Werkzeug/x Python/y` indicates the dev server, not necessarily debug.
- **Django DEBUG=True**: 500 page text "You're seeing this error because you have DEBUG = True in your Django settings file"; 404 page "Using the URLconf defined in ..." listing URL patterns.
- **Express (NODE_ENV≠production)**: 500 body `<pre>Error: ...<br> &nbsp; &nbsp;at ...` with stack frames; 404 `Cannot GET /path`; `X-Powered-By: Express`.
- **FastAPI/Starlette debug=True**: traceback HTML/plain text on 500. Always-on `/docs`, `/redoc`, `/openapi.json` (configuration exposure, not debug).
- **Next.js**: `X-Powered-By: Next.js`; dev-server artifacts (`/_next/webpack-hmr`, `__nextjs_original-stack-frame`) only under `next dev`.
- **Rails dev**: "Action Controller: Exception caught"; `/rails/info/routes`; web-console.
- **Laravel APP_DEBUG=true**: Ignition / Laravel error page with stack and env; `/_ignition/health-check`, `/_ignition/execute-solution` (legacy Ignition).
- **Spring Boot**: "Whitelabel Error Page" (the default, not a debug signal); `/actuator`, `/actuator/env`, `/actuator/heapdump` when exposure is widened; `trace`/stack fields in JSON error bodies when `server.error.include-stacktrace=always`.
- **PHP display_errors=On**: "Fatal error: Uncaught ... in /path/file.php on line N", "Warning: ... on line N"; `X-Powered-By: PHP/8.x`.
- **Go net/http / Gin**: no debug page. `/debug/pprof/` only if `net/http/pprof` is imported. Gin debug mode logs to stdout, not HTTP.

### Inferences
- For grading accuracy, the Flask/Werkzeug console is the best "debug" check of all candidates. It is binary, deterministic, high-severity (RCE), and Codex frequently emits `app.run(debug=True)` [GK]. Django's equivalent is equally deterministic but defaults to ON in the scaffold [GK], so it measures "did the prompt ask to turn DEBUG off" rather than "did the AI add something insecure". That is still a lever, but an inverted one.
- Go has no debug-page lever at all, which removes one cheap check.

### Gaps
- The fingerprint strings above were not re-verified against current versions (Werkzeug 3.1, Django 6.1, Express 5, Laravel 12's error page, Next.js 16) in this session. They should be confirmed by booting a scaffold of each.
- No source was found on how often Codex/other agents leave debug mode on per framework.
