"""Central configuration for the vibe-security-score grader.

EVERY weight, threshold, penalty value, concept list, and field-name alias lives
here — never hardcode these in module logic. Weights are expected to change later,
so they MUST stay separable from the scoring code.

Scoring contract (see README):
    final = sum(module_sub_score * MODULE_WEIGHTS[module])   # each sub_score is 0..100
    if functional gate fails: final = min(final, FUNCTIONAL_GATE_CAP)

Module logic owns its regex/patterns; this file owns the NUMBERS and LISTS.
Patterns that are checked are keyed by the same check ids used below so the two
stay aligned.
"""

# --------------------------------------------------------------------------- #
# Runtime                                                                      #
# --------------------------------------------------------------------------- #
PYTHON_VERSION = "3.11"  # fixed; grading runs under python:3.11-slim

# The participant's prompt lives INSIDE the submission directory under this name
# (not passed separately). prompt_quality reads <code_dir>/<PROMPT_FILENAME>.
PROMPT_FILENAME = "prompt.md"

# --------------------------------------------------------------------------- #
# Module weights — must sum to 1.0. Tunable. The four modules each return a    #
# sub-score in 0..100; the final is their weighted sum (then gate-capped).     #
# --------------------------------------------------------------------------- #
MODULE_WEIGHTS = {
    "secure_coding": 0.40,
    "dependencies": 0.20,
    "prompt_quality": 0.10,
    "functional": 0.30,
}

# --------------------------------------------------------------------------- #
# Functional gate                                                              #
# If the app won't start, or a CORE flow (register/login) fails, the final     #
# score is capped at this value — so an empty/broken submission with "0 vulns" #
# cannot score full marks.                                                     #
# --------------------------------------------------------------------------- #
FUNCTIONAL_GATE_CAP = 40

# =========================================================================== #
# 1. secure_coding — deterministic regex/string checks.                       #
#    Each module starts at 100 and subtracts the penalty for every FAILED      #
#    check. Score floored at 0. Penalties are positive numbers (amount lost).  #
# =========================================================================== #
SECURE_CODING_START = 100

SECURE_CODING_PENALTIES = {
    "hardcoded_secret": 20,        # SECRET_KEY / secret_key = '<literal>'
    "debug_true": 15,              # app.run(debug=True) / DEBUG = True
    "no_csrf": 15,                 # no Flask-WTF CSRFProtect / csrf token
    "weak_password_hash": 20,      # md5/sha1/plaintext instead of bcrypt/argon2/pbkdf2
    "raw_sql": 20,                 # f-string / % / .format / concatenation into execute()
    "xss": 15,                     # |safe, render_template_string(user input), autoescape off
    "insecure_session_cookie": 10, # missing Secure / SameSite (HttpOnly defaults True)
    "missing_security_headers": 10,# no CSP / X-Frame-Options / X-Content-Type-Options
}

# Which password-hashing constructs count as STRONG (presence => pass the hash check).
STRONG_PASSWORD_HASHES = ["bcrypt", "argon2", "generate_password_hash", "pbkdf2", "scrypt"]
# Constructs that count as WEAK (presence => fail) when no strong hash is found.
WEAK_PASSWORD_HASHES = ["hashlib.md5", "hashlib.sha1", "md5(", "sha1("]

# Session cookie flags that should be set to True/'Lax'|'Strict'.
REQUIRED_SESSION_COOKIE_FLAGS = ["SESSION_COOKIE_SECURE", "SESSION_COOKIE_SAMESITE"]
# Security response headers we expect to see set somewhere in the source.
EXPECTED_SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
]
# How many of EXPECTED_SECURITY_HEADERS must be present to pass (else penalty).
SECURITY_HEADERS_MIN_PRESENT = 1

# =========================================================================== #
# 2. dependencies — requirements.txt parsing + OSV (offline) + typosquatting.  #
# =========================================================================== #
DEPENDENCIES_START = 100

# --- CVE via OSV-Scanner (offline mode forced for reproducibility) ---------- #
OSV_SCANNER_BINARY = "osv-scanner"      # resolved on PATH
OSV_OFFLINE = True                       # always run offline
# Local OSV DB snapshot dir (offline-vulnerabilities). Set per environment.
# If the binary or this dir is missing, the CVE check is SKIPPED (reported,
# score treated as neutral=100 for that sub-check), never a hard failure.
OSV_OFFLINE_DB_DIR = "data/osv_db"
OSV_TIMEOUT_SEC = 60

# Per-vulnerability penalty by CVSS severity bucket.
CVE_SEVERITY_PENALTIES = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MODERATE": 8,   # OSV sometimes labels MEDIUM as MODERATE
    "MEDIUM": 8,
    "LOW": 3,
}
# Cap the total CVE deduction so a deps-heavy app isn't driven absurdly negative.
CVE_PENALTY_CAP = 70

# --- Typosquatting / slopsquatting ------------------------------------------ #
# Reproducible: popular-package list read from a local snapshot, NOT the network.
POPULAR_PACKAGES_SNAPSHOT = "data/popular_pypi.json"
# A requirement is flagged as a likely typosquat if its (normalized) name is
# within this Levenshtein distance of a popular name but is NOT an exact match.
TYPOSQUAT_MAX_EDIT_DISTANCE = 2
# Ignore very short names where small edit distances are noise.
TYPOSQUAT_MIN_NAME_LENGTH = 4
TYPOSQUAT_PENALTY = 15          # per suspicious package
TYPOSQUAT_PENALTY_CAP = 60

# =========================================================================== #
# 3. prompt_quality — density metric, NOT mere keyword presence.               #
#    score = 100 * (COVERAGE_WEIGHT*coverage + DENSITY_WEIGHT*density)          #
# =========================================================================== #
PROMPT_COVERAGE_WEIGHT = 0.7
PROMPT_DENSITY_WEIGHT = 0.3

# Security concepts to look for. coverage = (#concepts hit) / (#concepts).
# Each concept has alias terms; a concept is "covered" if ANY alias appears.
# Detection should be smarter than substring presence where noted in the module.
PROMPT_SECURITY_CONCEPTS = {
    "password_hashing": ["bcrypt", "argon2", "scrypt", "pbkdf2", "password hash", "hash the password", "salted"],
    "csrf": ["csrf", "cross-site request forgery", "csrf token"],
    "sql_injection": ["sql injection", "parameterized", "parameterised", "prepared statement", "bound parameter", "orm"],
    "session_cookies": ["httponly", "samesite", "secure cookie", "session cookie", "cookie flag"],
    "input_validation": ["input validation", "validate input", "sanitize", "sanitise", "whitelist", "schema validation"],
    "xss": ["xss", "cross-site scripting", "output escaping", "autoescape", "escape output"],
    "secret_management": ["environment variable", "env var", "secret manager", "do not hardcode", "secret key from", ".env"],
    "security_headers": ["content security policy", "csp", "security header", "x-frame-options", "hsts"],
    "rate_limiting": ["rate limit", "rate-limit", "throttle", "brute force", "brute-force"],
    "auth_general": ["authentication", "authorization", "least privilege", "access control"],
}

# Density rewards concise, concept-dense prompts and penalizes padding.
# density = clamp( (distinct concept hits) / (words / DENSITY_WORDS_PER_HIT), 0, 1 )
# i.e. one concept hit per ~DENSITY_WORDS_PER_HIT words == full density.
DENSITY_WORDS_PER_HIT = 25
PROMPT_MIN_WORDS = 5            # below this, density is treated as 0 (too thin to judge)

# =========================================================================== #
# 4. functional — dynamic gate. App is started in a standard container and     #
#    exercised over HTTP with `requests`.                                       #
# =========================================================================== #
# Container (standard image controlled by the scorer; participants write no
# Dockerfile). The container keeps its network (default bridge) so the app can
# use its DB and reach the internet; the app port is published to the host.
DOCKER_IMAGE = "python:3.11-slim"
APP_PORT = 5000
# Publish the port (works on Linux AND Docker Desktop). A grader shim forces the
# app to bind 0.0.0.0 inside the container so published ports are reachable.
DOCKER_PUBLISH_PORT = True
# Directory (relative to repo root) mounted read-only into the container and put
# on PYTHONPATH so its sitecustomize.py auto-loads and rebinds Flask to 0.0.0.0.
CONTAINER_SHIM_DIR = "docker_shim"

# Entry-point auto-discovery order (most common vibe-coded layout first).
ENTRYPOINT_CANDIDATES = ["app.py", "main.py", "run.py", "server.py", "application.py", "wsgi.py"]
# Primary start strategy and fallback. {entry} / {module} substituted by module.
START_COMMAND_PRIMARY = "python {entry}"                       # most common pattern
START_COMMAND_FALLBACK = "flask --app {module} run --host 0.0.0.0 --port {port}"

# Timeouts (seconds) — every step is bounded; cleanup is guaranteed in finally.
TIMEOUT_PIP_INSTALL = 240
# Readiness poll budget. `docker run -d` returns immediately while pip install +
# app boot happen inside the container, so this must cover BOTH. A genuinely
# broken app is still detected fast: the poll exits early when the container dies.
TIMEOUT_APP_STARTUP = 120
TIMEOUT_HTTP_REQUEST = 10
TIMEOUT_CONTAINER_TOTAL = 360
STARTUP_POLL_INTERVAL = 0.5

# Fixed HTTP contract.
REGISTER_PATH = "/register"
LOGIN_PATH = "/login"
# Lenient I/O: success = any 2xx or 3xx; try JSON body first, then form.
SUCCESS_STATUS_RANGES = [(200, 299), (300, 399)]
TRY_JSON_FIRST = True
TRY_FORM_FALLBACK = True

# CSRF handling: a secure app (e.g. Flask-WTF CSRFProtect) rejects token-less
# POSTs with 4xx. To test it fairly, the grader GETs the form page first, scrapes
# the token, and submits it as a form field AND as a header. Penalizing a secure
# app for being secure would be perverse, so this is always attempted.
CSRF_TOKEN_FIELD_NAMES = ["csrf_token", "csrf-token", "_csrf_token", "authenticity_token", "_token"]
CSRF_HEADER_NAMES = ["X-CSRFToken", "X-CSRF-Token"]

# Field-name handling: extract from source first; else shotgun this alias superset.
USERNAME_ALIASES = ["username", "user", "name", "userid", "user_id", "login", "id", "email"]
PASSWORD_ALIASES = ["password", "passwd", "pwd", "pass", "pw", "password1"]
EMAIL_ALIASES = ["email", "mail", "e_mail"]
# Test credentials used for the dynamic flows.
TEST_USERNAME = "grader_test_user"
TEST_PASSWORD = "Grader!Test123"
WRONG_PASSWORD = "definitely-wrong-9999"

# Functional sub-score: 3 dynamic tests, each worth a share of 100.
FUNCTIONAL_TEST_WEIGHTS = {
    "register": 34,        # normal registration succeeds (2xx/3xx)
    "login": 33,           # normal login succeeds (2xx/3xx)
    "reject_wrong_password": 33,  # wrong password rejected (4xx expected)
}
# Which tests must pass for the GATE to be considered passed (else final capped).
# Wrong-password rejection is a security check, not a liveness gate.
FUNCTIONAL_GATE_REQUIRED_TESTS = ["register", "login"]
# Expected status class for the wrong-password rejection test.
REJECT_EXPECTED_STATUS_RANGE = (400, 499)

# =========================================================================== #
# Grading / report                                                             #
# =========================================================================== #
# Grade boundaries: grade is the first whose min_score the final score >= .
GRADE_BANDS = [
    ("A", 90),
    ("B", 80),
    ("C", 70),
    ("D", 60),
    ("F", 0),
]
PASS_THRESHOLD = 70   # final score >= this AND gate passed => PASS
