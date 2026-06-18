"""Dynamic functional gate for the vibe-security-score grader.

Starts the participant's Flask app inside a standard Docker container
(python:3.11-slim) and exercises it over HTTP with ``requests``.

Contract: analyze(code_dir: str) -> dict
  {
      "score": float,       # 0..100
      "findings": [...],    # one Finding per check
      "gate_passed": bool,  # True only when all FUNCTIONAL_GATE_REQUIRED_TESTS pass
  }

Design notes:
- Every subprocess call is timeout-bounded; cleanup is guaranteed in a finally
  block — no leaked containers even on exception.
- The app port is published to the host (-p PORT:PORT), which works on Linux and
  Docker Desktop alike. A mounted shim (docker_shim/sitecustomize.py) rebinds the
  app's Flask app.run() to 0.0.0.0 so the published port is reachable even if the
  submission hardcoded 127.0.0.1.
- Field-name extraction uses a shotgun approach: the union of all
  USERNAME_ALIASES / PASSWORD_ALIASES is always sent, supplemented by any names
  extracted from the app source / templates, so apps using nonstandard names
  like ``name``/``pwd`` are covered without special-casing.
"""

import json
import os
import re
import shutil
import subprocess
import time
import uuid

import requests

from config import (
    APP_PORT,
    CONTAINER_SHIM_DIR,
    CSRF_HEADER_NAMES,
    CSRF_TOKEN_FIELD_NAMES,
    DOCKER_IMAGE,
    DOCKER_PUBLISH_PORT,
    EMAIL_ALIASES,
    ENTRYPOINT_CANDIDATES,
    FUNCTIONAL_GATE_REQUIRED_TESTS,
    FUNCTIONAL_TEST_WEIGHTS,
    LOGIN_PATH,
    PASSWORD_ALIASES,
    REGISTER_PATH,
    REJECT_EXPECTED_STATUS_RANGE,
    START_COMMAND_FALLBACK,
    START_COMMAND_PRIMARY,
    STARTUP_POLL_INTERVAL,
    SUCCESS_STATUS_RANGES,
    TEST_PASSWORD,
    TEST_USERNAME,
    TIMEOUT_APP_STARTUP,
    TIMEOUT_CONTAINER_TOTAL,
    TIMEOUT_HTTP_REQUEST,
    TIMEOUT_PIP_INSTALL,
    TRY_FORM_FALLBACK,
    TRY_JSON_FIRST,
    USERNAME_ALIASES,
    WRONG_PASSWORD,
)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TEST_EMAIL = "grader_test@example.com"


def _make_finding(
    fid: str,
    label: str,
    passed: bool,
    penalty: float,
    reason: str,
    evidence: str | None = None,
    skipped: bool = False,
) -> dict:
    """Return a Finding dict matching the module contract."""
    f: dict = {
        "id": fid,
        "label": label,
        "passed": passed,
        "penalty": penalty,
        "reason": reason,
        "evidence": evidence,
    }
    if skipped:
        f["skipped"] = True
    return f


def _make_session() -> requests.Session:
    """A plain session; Secure cookies are declassified per-request (see below)."""
    return requests.Session()


def _declassify_cookies(session: requests.Session) -> None:
    """Clear the Secure flag on stored cookies so they are sent over plain HTTP.

    Submissions correctly set SESSION_COOKIE_SECURE=True, but the grader talks to
    the container over HTTP, so requests would otherwise never send the session
    cookie back — and the CSRF token is bound to that session, so login/register on
    a secure app would fail with "CSRF session token is missing". A custom cookie
    policy does not survive requests' per-request jar merge, and a response hook
    runs before the new cookie is stored, so we clear the flag on the jar
    immediately BEFORE each request instead. Transport security is not what the
    functional gate scores.
    """
    for cookie in session.cookies:
        if cookie.secure:
            cookie.secure = False


def _is_success_status(status: int) -> bool:
    """Return True if *status* falls within any SUCCESS_STATUS_RANGES range."""
    return any(lo <= status <= hi for lo, hi in SUCCESS_STATUS_RANGES)


def _is_reject_status(status: int) -> bool:
    """Return True if *status* falls within REJECT_EXPECTED_STATUS_RANGE (4xx)."""
    lo, hi = REJECT_EXPECTED_STATUS_RANGE
    return lo <= status <= hi


def _run(args: list[str], timeout: int, **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess with a hard timeout; raise on non-zero exit."""
    return subprocess.run(
        args,
        timeout=timeout,
        check=True,
        capture_output=True,
        text=True,
        **kwargs,
    )


def _run_safe(args: list[str], timeout: int, **kwargs) -> subprocess.CompletedProcess | None:
    """Like _run but swallows errors and returns None on failure."""
    try:
        return subprocess.run(
            args,
            timeout=timeout,
            capture_output=True,
            text=True,
            **kwargs,
        )
    except Exception:
        return None


def _docker_available() -> bool:
    """Return True if docker is on PATH AND the daemon responds."""
    if not shutil.which("docker"):
        return False
    result = _run_safe(["docker", "info"], timeout=10)
    return result is not None and result.returncode == 0


# ---------------------------------------------------------------------------
# Field-name extraction
# ---------------------------------------------------------------------------

def _extract_field_names(code_dir: str) -> set[str]:
    """Best-effort extraction of form / JSON field names from the app source.

    Scans .py and .html files for:
    - request.form['key'] / request.form.get('key')
    - request.json['key'] / get_json()['key']
    - <input name="key"> in templates

    Returns a set of raw name strings found (lowercased).
    """
    names: set[str] = set()

    # Patterns for Python source
    py_patterns = [
        re.compile(r'request\.form\[[\'"]([\w_-]+)[\'"]\]'),
        re.compile(r'request\.form\.get\([\'"]([\w_-]+)[\'"]'),
        re.compile(r'request\.json\[[\'"]([\w_-]+)[\'"]\]'),
        re.compile(r'get_json\(\)\[[\'"]([\w_-]+)[\'"]\]'),
        re.compile(r'\.get\([\'"]([\w_-]+)[\'"]'),  # dict.get('key')
    ]
    # Pattern for HTML templates
    html_pattern = re.compile(r'<input[^>]+name=["\']([^"\']+)["\']', re.IGNORECASE)

    for root, _dirs, files in os.walk(code_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                continue

            if fname.endswith(".py"):
                for pat in py_patterns:
                    for m in pat.finditer(content):
                        names.add(m.group(1).lower())
            elif fname.endswith((".html", ".htm", ".jinja2", ".jinja")):
                for m in html_pattern.finditer(content):
                    names.add(m.group(1).lower())

    return names


def _build_payload(
    username: str,
    password: str,
    extra_names: set[str] | None = None,
) -> dict:
    """Build a shotgun payload covering all known username/password aliases.

    The union of USERNAME_ALIASES and PASSWORD_ALIASES is always included.
    Any additional extracted field names are mapped heuristically:
    - names that look like password fields get the password value
    - everything else gets the username value
    - email-looking names get a test email address
    """
    payload: dict[str, str] = {}

    # Always include every alias
    for alias in USERNAME_ALIASES:
        payload[alias] = username
    for alias in PASSWORD_ALIASES:
        payload[alias] = password
    for alias in EMAIL_ALIASES:
        payload[alias] = _TEST_EMAIL

    # Supplement with extracted names
    if extra_names:
        password_hints = {"pass", "pwd", "pw", "password", "passwd", "secret"}
        email_hints = {"email", "mail", "e_mail"}
        csrf_names = {n.lower() for n in CSRF_TOKEN_FIELD_NAMES}
        for name in extra_names:
            if name in payload:
                continue  # already set
            if name.lower() in csrf_names:
                continue  # never feed a credential value into a CSRF field
            if any(hint in name for hint in password_hints):
                payload[name] = password
            elif any(hint in name for hint in email_hints):
                payload[name] = _TEST_EMAIL
            else:
                payload[name] = username

    return payload


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

_CSRF_INPUT_RE = re.compile(
    r'<input[^>]*\bname=["\'](?P<name>[\w\-]+)["\'][^>]*\bvalue=["\'](?P<value>[^"\']+)["\']',
    re.IGNORECASE,
)
_CSRF_INPUT_RE_REV = re.compile(
    r'<input[^>]*\bvalue=["\'](?P<value>[^"\']+)["\'][^>]*\bname=["\'](?P<name>[\w\-]+)["\']',
    re.IGNORECASE,
)
_CSRF_META_RE = re.compile(
    r'<meta[^>]*\bname=["\'](?P<name>csrf[\w\-]*)["\'][^>]*\bcontent=["\'](?P<value>[^"\']+)["\']',
    re.IGNORECASE,
)


def _fetch_csrf_token(session: requests.Session, url: str) -> str | None:
    """GET *url* and scrape a CSRF token from the returned HTML, if present.

    Looks for a hidden input or <meta> whose name matches one of
    CSRF_TOKEN_FIELD_NAMES (case-insensitive). Returns the token value, or None
    if the page has none / can't be fetched. Uses *session* so the cookie that
    the token is bound to is retained for the subsequent POST.
    """
    wanted = {n.lower() for n in CSRF_TOKEN_FIELD_NAMES}
    _declassify_cookies(session)
    try:
        resp = session.get(url, timeout=TIMEOUT_HTTP_REQUEST, allow_redirects=True)
    except requests.RequestException:
        return None
    html = resp.text or ""
    for pattern in (_CSRF_INPUT_RE, _CSRF_INPUT_RE_REV, _CSRF_META_RE):
        for m in pattern.finditer(html):
            if m.group("name").lower() in wanted:
                return m.group("value")
    return None


def _post(
    session: requests.Session,
    url: str,
    payload: dict,
    csrf_token: str | None = None,
) -> int | None:
    """POST *payload* to *url*; try JSON first (if configured) then form-encoded.

    When *csrf_token* is given it is sent both as a form field (under every name
    in CSRF_TOKEN_FIELD_NAMES) and as each header in CSRF_HEADER_NAMES, so a
    CSRF-protected app (e.g. Flask-WTF) accepts the request.

    Returns the HTTP status code of the most-successful attempt, or None on
    connection error.  «Most-successful» = prefers 2xx/3xx over 4xx/5xx.
    """
    best_status: int | None = None

    headers: dict[str, str] = {}
    form_payload = dict(payload)
    if csrf_token:
        for header in CSRF_HEADER_NAMES:
            headers[header] = csrf_token
        # Assign (not setdefault): a CSRF field may already be present from the
        # shotgun payload — it MUST carry the real token, not a credential value.
        for field in CSRF_TOKEN_FIELD_NAMES:
            form_payload[field] = csrf_token

    def _try(status: int | None) -> None:
        nonlocal best_status
        if status is None:
            return
        if best_status is None:
            best_status = status
            return
        # Prefer success over failure
        if _is_success_status(status) and not _is_success_status(best_status):
            best_status = status

    if TRY_JSON_FIRST:
        _declassify_cookies(session)
        try:
            resp = session.post(url, json=payload, headers=headers,
                                timeout=TIMEOUT_HTTP_REQUEST, allow_redirects=True)
            _try(resp.status_code)
        except requests.RequestException:
            pass

    if TRY_FORM_FALLBACK:
        _declassify_cookies(session)
        try:
            resp = session.post(url, data=form_payload, headers=headers,
                                timeout=TIMEOUT_HTTP_REQUEST, allow_redirects=True)
            _try(resp.status_code)
        except requests.RequestException:
            pass

    return best_status


# ---------------------------------------------------------------------------
# Docker container management
# ---------------------------------------------------------------------------

def _discover_entrypoint(code_dir: str) -> tuple[str, str]:
    """Return (entry_filename, module_name) for the first matching candidate."""
    for candidate in ENTRYPOINT_CANDIDATES:
        if os.path.isfile(os.path.join(code_dir, candidate)):
            module = os.path.splitext(candidate)[0]
            return candidate, module
    # Fallback: assume app.py even if missing (Docker will fail, which is handled)
    return ENTRYPOINT_CANDIDATES[0], os.path.splitext(ENTRYPOINT_CANDIDATES[0])[0]


def _build_bootstrap(code_dir: str, entry: str, module: str) -> str:
    """Build the shell bootstrap command for docker run.

    If requirements.txt is present, pip install first; then try PRIMARY start
    command and fall back to the flask CLI if it exits/fails.
    """
    primary = START_COMMAND_PRIMARY.format(entry=entry)
    fallback = START_COMMAND_FALLBACK.format(module=module, port=APP_PORT)

    has_req = os.path.isfile(os.path.join(code_dir, "requirements.txt"))
    pip_step = "pip install -q -r requirements.txt 2>/dev/null; " if has_req else ""

    # Use ( primary || fallback ) so the fallback fires if primary exits non-zero
    return f"{pip_step}( {primary} || {fallback} )"


def _get_docker_logs(container_name: str, tail: int = 15) -> str:
    """Return the last *tail* lines of docker logs for *container_name*."""
    result = _run_safe(
        ["docker", "logs", "--tail", str(tail), container_name],
        timeout=10,
    )
    if result is None:
        return "(로그 수집 실패)"
    return (result.stdout + result.stderr).strip() or "(로그 없음)"


def _container_is_running(container_name: str) -> bool:
    """Return True if the named container is still running."""
    result = _run_safe(
        ["docker", "inspect", "-f", "{{.State.Running}}", container_name],
        timeout=5,
    )
    if result is None or result.returncode != 0:
        return False
    return result.stdout.strip().lower() == "true"


def _start_container(
    container_name: str,
    code_dir: str,
    entry: str,
    module: str,
) -> subprocess.CompletedProcess:
    """Launch the Docker container in detached mode.

    Networking: the app port is published to the host (``-p PORT:PORT``), which
    works on both Linux and Docker Desktop. A read-only shim directory is mounted
    and placed on PYTHONPATH; its sitecustomize.py rebinds Flask's app.run() to
    0.0.0.0 inside the container so the published port is reachable regardless of
    what host the submission hardcoded. The default bridge network keeps the
    container online for its DB / outbound needs.
    """
    bootstrap = _build_bootstrap(code_dir, entry, module)
    abs_code_dir = os.path.abspath(code_dir)
    # docker_shim/ lives at the repo root, one level above this module's package.
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    abs_shim_dir = os.path.join(repo_root, CONTAINER_SHIM_DIR)

    cmd = ["docker", "run", "-d", "--name", container_name]

    if DOCKER_PUBLISH_PORT:
        cmd += ["-p", f"{APP_PORT}:{APP_PORT}"]

    cmd += [
        # Grader shim: rebind Flask app.run() to 0.0.0.0:APP_PORT (auto-loaded
        # via sitecustomize on PYTHONPATH).
        "-e", f"GRADER_APP_PORT={APP_PORT}",
        "-e", "PYTHONPATH=/grader_shim",
        # Help the `flask run` fallback bind/serve on the right interface/port.
        "-e", f"FLASK_RUN_PORT={APP_PORT}",
        "-e", "FLASK_RUN_HOST=0.0.0.0",
        "-v", f"{abs_code_dir}:/app",
        "-v", f"{abs_shim_dir}:/grader_shim:ro",
        "-w", "/app",
        DOCKER_IMAGE,
        "sh", "-c", bootstrap,
    ]

    return subprocess.run(
        cmd,
        timeout=TIMEOUT_PIP_INSTALL + 30,  # generous: includes pip install
        check=True,
        capture_output=True,
        text=True,
    )


def _cleanup_container(container_name: str) -> None:
    """Remove the container forcefully; ignore all errors."""
    _run_safe(["docker", "rm", "-f", container_name], timeout=15)


def _wait_for_startup(base_url: str, container_name: str) -> tuple[bool, str]:
    """Poll *base_url* until the app responds or the startup timeout elapses.

    Returns (up: bool, evidence: str).
    - up=True as soon as ANY HTTP response is received (even 404/500).
    - Stops early if the container has already exited.
    """
    deadline = time.monotonic() + TIMEOUT_APP_STARTUP
    last_error = ""

    while time.monotonic() < deadline:
        # Check if the container already died
        if not _container_is_running(container_name):
            logs = _get_docker_logs(container_name, tail=15)
            return False, logs

        try:
            requests.get(base_url + "/", timeout=STARTUP_POLL_INTERVAL * 2)
            return True, "앱이 HTTP 응답을 반환했습니다."
        except requests.ConnectionError as exc:
            last_error = str(exc)
        except requests.Timeout:
            last_error = "연결 타임아웃"
        except requests.RequestException as exc:
            # Any HTTP response (even error) means the server is up
            if hasattr(exc, "response") and exc.response is not None:
                return True, "앱이 HTTP 응답을 반환했습니다."
            last_error = str(exc)

        time.sleep(STARTUP_POLL_INTERVAL)

    # Timed out
    logs = _get_docker_logs(container_name, tail=15)
    return False, logs or last_error


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(code_dir: str) -> dict:
    """Run the functional gate against the app in *code_dir*.

    Steps:
    1. Guard: return docker_unavailable if Docker is not accessible.
    2. Discover entrypoint; extract field names from source/templates.
    3. Start a detached Docker container running the app.
    4. Poll for readiness; on startup failure emit failed findings.
    5. If up, run three HTTP tests: register, login, reject_wrong_password.
    6. Compute score and gate result.
    7. Guarantee container cleanup in finally.

    Returns a dict matching the functional module contract.
    """
    # ------------------------------------------------------------------
    # 1. PRECONDITION: Docker must be available
    # ------------------------------------------------------------------
    if not _docker_available():
        finding = _make_finding(
            fid="docker_unavailable",
            label="Docker 데몬 가용성",
            passed=False,
            penalty=0,
            reason=(
                "Docker 데몬 미가용 — 기능 검사 생략. "
                "게이트 미통과로 간주(최종 점수 캡)."
            ),
            skipped=True,
        )
        return {"score": 0, "gate_passed": False, "findings": [finding]}

    # ------------------------------------------------------------------
    # 2. Entrypoint discovery + field-name extraction
    # ------------------------------------------------------------------
    entry, module = _discover_entrypoint(code_dir)
    extracted_names = _extract_field_names(code_dir)

    base_url = f"http://127.0.0.1:{APP_PORT}"
    container_name = f"vibe_grader_{uuid.uuid4().hex[:12]}"

    # We collect all findings here; tests that we couldn't reach are skipped.
    findings: list[dict] = []

    try:
        # --------------------------------------------------------------
        # 3. Start container
        # --------------------------------------------------------------
        try:
            _start_container(container_name, code_dir, entry, module)
        except subprocess.TimeoutExpired:
            logs = _get_docker_logs(container_name, tail=15)
            findings.append(_make_finding(
                fid="app_startup",
                label="앱 시작",
                passed=False,
                penalty=0,
                reason="Docker 컨테이너 시작 명령이 타임아웃되었습니다.",
                evidence=logs,
            ))
            _add_skipped_test_findings(findings)
            return {"score": 0, "gate_passed": False, "findings": findings}
        except subprocess.CalledProcessError as exc:
            findings.append(_make_finding(
                fid="app_startup",
                label="앱 시작",
                passed=False,
                penalty=0,
                reason="Docker 컨테이너를 시작하지 못했습니다.",
                evidence=(exc.stderr or exc.stdout or "").strip()[-500:],
            ))
            _add_skipped_test_findings(findings)
            return {"score": 0, "gate_passed": False, "findings": findings}

        # --------------------------------------------------------------
        # 4. Wait for readiness
        # --------------------------------------------------------------
        up, startup_evidence = _wait_for_startup(base_url, container_name)

        if not up:
            findings.append(_make_finding(
                fid="app_startup",
                label="앱 시작",
                passed=False,
                penalty=0,
                reason=(
                    f"앱이 {TIMEOUT_APP_STARTUP}초 내에 HTTP 응답을 반환하지 않았습니다. "
                    "ImportError나 설정 오류로 인해 서버가 실행되지 않은 것 같습니다."
                ),
                evidence=startup_evidence[-800:] if startup_evidence else None,
            ))
            _add_skipped_test_findings(findings)
            return {"score": 0, "gate_passed": False, "findings": findings}

        # App is up — record the startup success finding
        findings.append(_make_finding(
            fid="app_startup",
            label="앱 시작",
            passed=True,
            penalty=0,
            reason="Docker 컨테이너가 정상 시작되어 HTTP 응답을 반환했습니다.",
            evidence=startup_evidence,
        ))

        # --------------------------------------------------------------
        # 5. Run HTTP tests
        # --------------------------------------------------------------
        sess = _make_session()

        # Use a unique username per run so re-grading is idempotent even when the
        # app persists users in a file DB (a fixed name would hit "already exists"
        # / HTTP 409 on the second run).
        run_username = f"{TEST_USERNAME}_{uuid.uuid4().hex[:8]}"

        # Build payloads — use a shotgun union of all aliases + extracted names
        register_payload = _build_payload(run_username, TEST_PASSWORD, extracted_names)
        login_payload = _build_payload(run_username, TEST_PASSWORD, extracted_names)
        wrong_payload = _build_payload(run_username, WRONG_PASSWORD, extracted_names)

        # Fetch a CSRF token from each form page first (None if the app has no
        # CSRF protection) so secure, CSRF-protected apps accept our POSTs.
        register_token = _fetch_csrf_token(sess, base_url + REGISTER_PATH)
        register_status = _post(sess, base_url + REGISTER_PATH, register_payload,
                                csrf_token=register_token)

        login_token = _fetch_csrf_token(sess, base_url + LOGIN_PATH)
        login_status = _post(sess, base_url + LOGIN_PATH, login_payload,
                             csrf_token=login_token)

        reject_token = _fetch_csrf_token(sess, base_url + LOGIN_PATH)
        reject_status = _post(sess, base_url + LOGIN_PATH, wrong_payload,
                              csrf_token=reject_token)

        # --- register ---
        register_passed = register_status is not None and _is_success_status(register_status)
        findings.append(_make_finding(
            fid="register",
            label="회원가입 엔드포인트",
            passed=register_passed,
            penalty=0,
            reason=(
                f"회원가입 POST {REGISTER_PATH} — "
                + (
                    f"HTTP {register_status} 반환. "
                    + ("2xx/3xx 성공 응답입니다." if register_passed else "2xx/3xx 응답이 예상되었으나 다른 상태 코드가 반환되었습니다.")
                    if register_status is not None
                    else "응답을 받지 못했습니다 (연결 오류)."
                )
            ),
            evidence=str(register_status) if register_status is not None else None,
        ))

        # --- login ---
        login_passed = login_status is not None and _is_success_status(login_status)
        findings.append(_make_finding(
            fid="login",
            label="로그인 엔드포인트",
            passed=login_passed,
            penalty=0,
            reason=(
                f"로그인 POST {LOGIN_PATH} — "
                + (
                    f"HTTP {login_status} 반환. "
                    + ("2xx/3xx 성공 응답입니다." if login_passed else "2xx/3xx 응답이 예상되었으나 다른 상태 코드가 반환되었습니다.")
                    if login_status is not None
                    else "응답을 받지 못했습니다 (연결 오류)."
                )
            ),
            evidence=str(login_status) if login_status is not None else None,
        ))

        # --- reject_wrong_password ---
        reject_passed = reject_status is not None and _is_reject_status(reject_status)
        lo, hi = REJECT_EXPECTED_STATUS_RANGE
        findings.append(_make_finding(
            fid="reject_wrong_password",
            label="잘못된 비밀번호 거부",
            passed=reject_passed,
            penalty=0,
            reason=(
                f"잘못된 비밀번호로 로그인 POST {LOGIN_PATH} — "
                + (
                    f"HTTP {reject_status} 반환. "
                    + (
                        f"{lo}~{hi} 범위의 오류 응답으로 올바르게 거부했습니다."
                        if reject_passed
                        else f"{lo}~{hi} 범위의 응답이 예상되었습니다. "
                             f"앱이 잘못된 비밀번호를 거부하지 않아 보안 취약점이 있을 수 있습니다."
                    )
                    if reject_status is not None
                    else "응답을 받지 못했습니다 (연결 오류)."
                )
            ),
            evidence=str(reject_status) if reject_status is not None else None,
        ))

        # --------------------------------------------------------------
        # 6. Score + gate
        # --------------------------------------------------------------
        score = _compute_score(register_passed, login_passed, reject_passed)
        gate_passed = _check_gate(register_passed, login_passed)

        return {"score": score, "gate_passed": gate_passed, "findings": findings}

    finally:
        # ------------------------------------------------------------------
        # 9. CLEANUP — guaranteed; no leaked container/process.
        # ------------------------------------------------------------------
        _cleanup_container(container_name)


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

def _compute_score(register_passed: bool, login_passed: bool, reject_passed: bool) -> float:
    """Sum weights for each passed test to yield a 0..100 sub-score."""
    results = {
        "register": register_passed,
        "login": login_passed,
        "reject_wrong_password": reject_passed,
    }
    return float(sum(
        FUNCTIONAL_TEST_WEIGHTS[test]
        for test, passed in results.items()
        if passed
    ))


def _check_gate(register_passed: bool, login_passed: bool) -> bool:
    """Gate passes iff every FUNCTIONAL_GATE_REQUIRED_TESTS test passed."""
    results = {"register": register_passed, "login": login_passed}
    return all(results.get(t, False) for t in FUNCTIONAL_GATE_REQUIRED_TESTS)


def _add_skipped_test_findings(findings: list[dict]) -> None:
    """Append skipped findings for register, login, and reject_wrong_password.

    Called when the app failed to start, so tests could not run.
    """
    skipped_tests = [
        ("register", "회원가입 엔드포인트", "앱이 시작되지 않아 회원가입 테스트를 실행할 수 없습니다."),
        ("login", "로그인 엔드포인트", "앱이 시작되지 않아 로그인 테스트를 실행할 수 없습니다."),
        ("reject_wrong_password", "잘못된 비밀번호 거부", "앱이 시작되지 않아 거부 테스트를 실행할 수 없습니다."),
    ]
    for fid, label, reason in skipped_tests:
        findings.append(_make_finding(
            fid=fid,
            label=label,
            passed=False,
            penalty=0,
            reason=reason,
            skipped=True,
        ))
