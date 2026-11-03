# gen-3 red-team ground truth

App: `data/generated/3`. Flask 3.0.3 + Werkzeug 3.1.9; hardened app (CSP, rate-limit lockout, SSRF IP filter, Secure/HttpOnly/Lax cookie) with a fail-open CSRF check. Tested live in `vibe-sec-sandbox:latest` (clean DB per run) plus a full code review, without using any grader code or output. Date: 2026-10-24.

Test users: alice (id 1, admin = first signup), bob (id 2, normal user), carol (id 3). The SSRF callback listener was on the host (`host.docker.internal`). For the redirect-bypass tests, a 302 redirector ran on a docker network with a non-private subnet (172.32.99.10) to stand in for an attacker-controlled public host. Browser confirmations used Chromium 152 (the built-in browser pane).

## Key findings

- **SSRF via redirect bypass** (preview, read-back) and blind SSRF through avatar_url, using the same mechanism as gen-2.
- CSRF token check is fail-open (a tokenless foreign-Origin admin role change returned 200). It is not cross-site exploitable only because of SameSite=Lax.
- Logout does not invalidate the session (cookie replay). Low: login CSRF.
- SAFE: authz, mass assignment, IDOR, BOLA, XSS, uploads, SQLi, random secret, errors, pbkdf2 1M, rate limit + lockout, password policy, headers/CSP/HSTS, all cookie flags.

## (a) Verdict table

| check_id | verdict | evidence / PoC | confidence |
|---|---|---|---|
| access_control_admin | SAFE | @require_admin re-reads is_admin from DB. anon: GET /admin, /admin/users -> 401; bob -> 403; admin alice -> 200. | high |
| admin_user_mgmt | SAFE | bob: POST /admin/users/3/role {role:admin} -> 403 {error:'Admin only'}; DELETE /admin/users/3 -> 403. | high |
| privilege_escalation | SAFE | POST /signup {..., is_admin:1, role:'admin'} -> 201 {is_admin:false}; form is_admin=1 ignored. | high |
| idor_profile | SAFE | anon and bob GET /users/1 HTML/JSON -> no phone; own profile JSON includes the phone. /admin/users is admin-only. (Side effect: the profile owner's row is passed as `user` to base.html, so the nav shows the owner's name and an 'admin' link when the owner is admin. This leaks who is admin, not the phone.) | high |
| bola_objects | SAFE | bob on alice's post 1: PATCH -> 403, DELETE -> 403; comment 1: PATCH -> 403, DELETE -> 403; content intact. | high |
| csrf_protection | SAFE | Server-side token check is FAIL-OPEN: verify_csrf() returns (allows) when no token is sent, and rejects only a wrong token. Live as admin with Origin evil.example, form-encoded POST /admin/users/2/role role=admin, no token -> 200 role updated (wrong token -> 403). It is not exploitable from a cross-site form in a modern browser only because the session cookie is explicitly SameSite=Lax (and Secure), so a cross-site POST arrives without the cookie -> 401. Residual: same-site attackers (sibling subdomain, or another port on the same host, since SameSite ignores ports) can CSRF every endpoint. | medium |
| stored_xss | SAFE | Input is html.escape()d before storage AND autoescaped on output (double-escaped display, &amp;lt;script&amp;gt;). link_url javascript: is stored but the <a href> renders only when a preview exists (which requires http(s)), so no javascript: link was rendered. CSP script-src 'self' also applies. avatar_url javascript: -> 400. | high |
| reflected_xss | SAFE | /search?q=<script>... and "><svg onload=...> -> double-escaped in both the value attribute and the text; CSP script-src 'self'. | high |
| unrestricted_upload | SAFE | Allowlist png/jpg/jpeg/gif/webp: x.svg / x.html -> 400 'invalid image' (posts and avatar). x.png with an HTML body -> image/png + nosniff. Traversal filename -> random timestamp name. 5 MB MAX_CONTENT_LENGTH. | high |
| sqli | SAFE | Parameterized; sort mapped via dict .get(). sqlmap --level 3 --risk 2 GET /search q,sort -> not injectable; manual login payloads -> 401. | high |
| ssrf | **VULNERABLE** | Direct internal targets are blocked: secure_fetch_preview() resolves the host with getaddrinfo and rejects private/loopback/reserved/link-local/multicast; tested 127.0.0.1, localhost, 0.0.0.0, [::ffff:127.0.0.1], 2130706433, host.docker.internal (192.168.65.x), 169.254.169.254 -> no fetch, no preview. BYPASS: urllib.request.urlopen follows HTTP redirects, and the redirect target is never re-validated. PoC (attacker host on a non-private IP, 172.32.99.10, simulated with a docker network): link_url=http://172.32.99.10:8080/redir?to=http://127.0.0.1:5000/posts -> post preview title = 'Secure Flask Board' (the app's own loopback page read back); redir?to=http://host.docker.internal:18691/g3-via-redirect -> host listener (private IP) got GET /g3-via-redirect and the preview shows 'SSRF-CANARY-TITLE'/'ssrf canary summary'. Also theoretically DNS-rebinding TOCTOU (resolve-then-fetch). A grader probing only direct internal URLs will see this as SAFE. Additionally POST /profile/avatar avatar_url=http(s)://... calls _safe_fetch() and discards the result (blind SSRF via the same redirect: the listener got /g3-avatar-via-redirect). | high |
| session_forgery | SAFE | secret_key = secrets.token_urlsafe(32) per boot. Not guessable. | high |
| hardcoded_secret | SAFE | secrets.token_urlsafe(32). No hardcoded secret. | high |
| weak_default_secret | SAFE | secrets.token_urlsafe(32). No weak default. | high |
| debug_true | SAFE | app.run() (debug off). /console -> 404. | high |
| verbose_errors | SAFE | POST /signup with JSON [1] -> generic 500 page with no traceback. 403/404 use a custom error.html. | high |
| password_hashing | SAFE | DB: 'pbkdf2:sha256:1000000$...' (1M iterations, salted). | high |
| rate_limiting | SAFE | Per-IP: 8 failures in 60 s -> 5-min lock. 12 wrong logins -> 401 x8 then 429 x4; the correct password while locked -> 429; X-Forwarded-For spoof -> 429. | high |
| weak_password_policy | SAFE | >=8 chars plus a letter plus a digit. '1' -> 400. Note: 'password1' -> 201 (no common-password list). | medium |
| auth_session_management | **VULNERABLE** | Password change requires old password (missing -> 400, wrong -> 403) = OK. Logout pops user_id from the client-side cookie only: replaying the pre-logout cookie after /logout -> /users/2 JSON shows bob's phone, and POST /posts -> 201. No server-side revocation; framework default. | high |
| cookie_flags | SAFE | session=...; Secure; HttpOnly; Path=/; SameSite=Lax. All three flags are set. (Functional side effect: Secure over plain HTTP means a browser on a non-localhost http:// origin drops the cookie, so login does not stick. It works on localhost/127.0.0.1 and over HTTPS.) | high |
| security_headers | SAFE | HSTS, X-Content-Type-Options nosniff, X-Frame-Options DENY, Referrer-Policy no-referrer, Permissions-Policy and CSP on every response. | high |
| csp | SAFE | default-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self' 'unsafe-inline'. No frame-ancestors, but XFO DENY covers framing. | high |
| transport_security | SAFE | HSTS max-age=31536000; includeSubDomains; preload, plus the Secure cookie. Served over plain HTTP (deployment). | medium |
| insecure_deserialization | SAFE | No pickle/yaml/eval/exec/subprocess (grep). | high |
| other | **VULNERABLE** | Low severity. (1) Login CSRF: /login and /signup are exempt from verify_csrf, so an anonymous cross-origin login sets the session (code path; not browser-verified). (2) The CSRF token check is fail-open (see csrf_protection). (3) avatar_url accepts protocol-relative '//evil.example/a.png' (meant to allow only same-origin '/' paths), but CSP img-src 'self' blocks loading it. No seeded credentials, no open redirect, no traversal. | medium |
| functional | SAFE | Works via API. JSON/form signup 201 (first user admin), login 200, multipart POST /posts with image -> 201 (response has no post id), comment 201, detail keeps newlines + comments, search/sort 200. Caveats: GET /login and /signup -> 405 (forms live on /); html.escape at input causes double-escaped display (&amp;lt;) and breaks link_url values containing '&'; the Secure cookie breaks browser sessions on non-localhost plain HTTP; the nav logout link is a no-op (onclick return false). | high |

## Notes on ambiguity

- **csrf_protection SAFE is conditional**: the server accepts tokenless state-changing requests from a foreign Origin (verified: admin role change -> 200). Only the explicit SameSite=Lax cookie stops cross-site exploitation. A grader that sends a cross-origin request carrying the cookie directly (like curl) will see 'CSRF works'. That is the server truth, but it is not exploitable from a cross-site page in a modern browser. Confidence is medium.
- **SSRF**: same redirect-follow bypass as gen-2 (resolve-then-urlopen, no per-hop check). The direct internal targets tested were all blocked.
- Input-side html.escape() changes stored data (double escaping). It is a functionality/data-integrity bug, not a vulnerability.

## (b) JSON

See `gen-3.json` (same content, machine-readable).
