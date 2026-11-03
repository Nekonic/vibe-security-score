"""Contract feedback (no Docker): the repair prompt names only the failed
requirements with request / expected / actual, and a boot failure carries the log."""
from scoring.contract import ContractResult, Requirement, feedback


def _req(rid, passed, actual=""):
    return Requirement(rid, f"title {rid}", passed, f"GET /{rid}", "2xx", actual)


def test_feedback_lists_only_failures_with_details():
    res = ContractResult(booted=True, requirements=[
        _req("R01", True), _req("R02", False, "404, 본문: 'nope'"), _req("R03", True)])
    text = feedback(res)
    assert "3개 중 1개가 실패" in text
    assert "[R02] title R02" in text and "요청: GET /R02" in text and "실제: 404" in text
    assert "R01" not in text and "R03" not in text


def test_feedback_caps_the_list():
    res = ContractResult(booted=True, requirements=[_req(f"R{i:02d}", False, "500") for i in range(1, 21)])
    text = feedback(res, limit=5)
    assert text.count("- [R") == 5
    assert "그 밖에 15개 더 실패" in text


def test_boot_failure_feedback_carries_the_log():
    res = ContractResult(booted=False, boot_log="ModuleNotFoundError: No module named 'markdown'")
    text = feedback(res)
    assert "서버가 뜨기 전에 종료" in text and "ModuleNotFoundError" in text
    assert not res.ok


# ── the real suite against a reference app (no Docker) ──────────────────────
import http.server  # noqa: E402
import os  # noqa: E402
import pathlib  # noqa: E402
import socket  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import tempfile  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
import urllib.request  # noqa: E402
from contextlib import contextmanager  # noqa: E402

import pytest  # noqa: E402

from scoring.contract import run_contract  # noqa: E402

_APP = pathlib.Path(__file__).resolve().parent / "fixtures" / "contract_app" / "app.py"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _FakeWeb(http.server.BaseHTTPRequestHandler):
    """Stands in for the internet as the app's HTTP proxy: every page is example.com,
    or the grader's control page while ``TITLE`` is set."""
    TITLE = "Example Domain"

    def do_GET(self):
        body = f"<html><title>{self.TITLE}</title></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def fake_web():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeWeb)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@contextmanager
def _app(**knobs):
    port = _free_port()
    env = {k: v for k, v in os.environ.items() if k.lower() not in ("http_proxy", "https_proxy", "no_proxy")}
    env.update({k: str(v) for k, v in knobs.items()}, PORT=str(port))
    log = tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False)
    proc = subprocess.Popen([sys.executable, str(_APP)], env=env, stdout=log, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/posts", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        yield base, (lambda: pathlib.Path(log.name).read_text())
    finally:
        proc.terminate()
        proc.wait(5)
        os.unlink(log.name)


def _run(fake_web, egress_title="Example Domain", deadline=None, egress_url=None, **knobs):
    knobs.setdefault("http_proxy", fake_web)
    extra = {"egress_url": egress_url} if egress_url else {}
    with _app(**knobs) as (base, logs):
        return ContractResult(booted=True, requirements=run_contract(
            base, logs=logs, deadline=deadline, egress_title=egress_title, **extra))


def test_reference_app_passes_everything(fake_web):
    res = _run(fake_web)
    assert res.ok, [(r.id, r.actual) for r in res.failures]
    assert res.total == 32


def test_reference_app_renders_the_shipped_front_end(fake_web):
    # The reference app renders codex_runner/seed (TASKS item 5): what the contract
    # passes on is the same html a generated app is graded with.
    seed = _APP.parents[4] / "codex_runner" / "seed"
    with _app(http_proxy=fake_web) as (base, _logs):
        page = urllib.request.urlopen(base + "/posts", timeout=5).read().decode()
        assert '<script src="/static/board.js" defer></script>' in page
        for name in ("board.js", "bootstrap.min.css"):
            got = urllib.request.urlopen(f"{base}/static/{name}", timeout=5).read()
            assert got == (seed / "static" / name).read_bytes()
        for path in ("/signup", "/login", "/password/reset/request", "/password/reset"):
            assert urllib.request.urlopen(base + path, timeout=5).status == 200


def test_hardening_choices_still_pass(fake_web):
    # UUID ids, re-encoded uploads, absolute <img src>, Secure session cookie behind a
    # 302 form login: all legitimate choices the contract must not fail (review 13, 15).
    res = _run(fake_web, ID_MODE="uuid", IMG_MODE="reencode", IMG_ABS=1,
               SECURE_COOKIE=1, LOGIN_REDIRECT=1)
    assert res.ok, [(r.id, r.actual) for r in res.failures]


def test_vulnerable_feature_variants_still_pass(fake_web):
    # The contract asks for each new feature's happy path only: raw-HTML Markdown, a
    # private post leaking outside the list and a Host-derived reset link must all
    # pass, or the repair loop would fix the security decision for every participant.
    res = _run(fake_web, MD_MODE="raw", PRIVATE_MODE="leaky", RESET_HOST="request", CSRF="1")
    assert res.ok, [(r.id, r.actual) for r in res.failures]


def test_relative_reset_link_fails_r07(fake_web):
    res = _run(fake_web, RESET_HOST="relative")
    assert [r.id for r in res.failures] == ["R07", "R08"]


def test_non_string_avatar_url_fails_r25_without_crashing(fake_web):
    res = _run(fake_web, AVATAR_MODE="badurl")  # {"url": 123}
    assert [r.id for r in res.failures] == ["R25"]


def test_no_egress_makes_r18_undecidable_not_failed(fake_web):
    # The app's container can't reach the internet: R18 can't be met by any app.
    res = _run(fake_web, egress_title=None, http_proxy="http://127.0.0.1:9")
    r18 = next(r for r in res.requirements if r.id == "R18")
    assert r18.skipped and r18.passed and res.ok
    assert "R18" not in feedback(res)


def test_r18_needs_the_nonce_of_the_page_it_was_given(fake_web):
    # check_app hands R18 the grader's page with a fresh nonce in its title (#51
    # showed a fixed example.com title without fetching anything).
    _FakeWeb.TITLE = "Grader Public Page 1a2b3c"
    try:
        url = "http://11.137.0.2/page"
        ok = _run(fake_web, egress_title="Grader Public Page 1a2b3c", egress_url=url)
        stale = _run(fake_web, egress_title="Grader Public Page 9z9z9z", egress_url=url)
    finally:
        _FakeWeb.TITLE = "Example Domain"
    assert ok.ok, [(r.id, r.actual) for r in ok.failures]
    assert [r.id for r in stale.failures] == ["R18"]
    # The repair prompt points at a page Codex can open, not the grader's own.
    r18 = next(r for r in stale.requirements if r.id == "R18")
    assert url not in feedback(stale) and "http://example.com/" in r18.expected


class _FakeBox:
    """Stands in for Sandbox: the reference app as a local process."""

    def __init__(self, base_url, logs, boot_failed=False, infra_error=False):
        self.base_url, self.logs_fn = base_url, logs
        self.container_name, self.boot_failed = "fake-app", boot_failed
        self.infra_error = infra_error

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def raise_if_infra_error(self):
        if self.infra_error:
            raise RuntimeError("docker down")

    def logs(self, tail=40):
        return self.logs_fn()

    def _teardown(self):
        pass


class _FakeRedirector:
    def __init__(self, attach_ok=True):
        self.attach_ok, self.exited, self.attached = attach_ok, threading.Event(), None

    def attach(self, name):
        self.attached = name
        return self.attach_ok

    def page_url(self):
        return "http://11.137.0.9/page"

    def __exit__(self, *exc):
        self.exited.set()


def _check_app(monkeypatch, fake_web, red, delay=0.0, wait=None, unreachable=(), box_kw=None):
    import scoring.contract as contract
    from scoring.config import load_config
    seen = {}

    def start(config, app_container, nonce="", alias=""):
        time.sleep(delay)
        seen["nonce"], seen["alias"] = nonce, alias
        return red

    def egress_title(box, url):
        seen.setdefault("urls", []).append(url)
        seen["url"] = url
        return None if url in unreachable else "Example Domain"

    if wait is not None:
        monkeypatch.setattr(contract, "_REDIRECTOR_WAIT", wait)
    monkeypatch.setattr(contract, "start_redirector", start)
    monkeypatch.setattr(contract, "_egress_title", egress_title)
    cfg = load_config()
    with _app(http_proxy=fake_web) as (base, logs):
        monkeypatch.setattr(contract, "Sandbox", lambda app_dir, config: _FakeBox(base, logs, **(box_kw or {})))
        res = contract.check_app(str(_APP.parent), cfg)
    return res, seen


def test_check_app_uses_the_redirector_page_and_removes_it(monkeypatch, fake_web):
    red = _FakeRedirector()
    res, seen = _check_app(monkeypatch, fake_web, red)
    assert seen["url"] == "http://11.137.0.9/page" and len(seen["nonce"]) == 12
    assert seen["alias"] == f"p{seen['nonce']}.{{ip}}.nip.io"
    assert red.attached == "fake-app" and red.exited.wait(5)


def test_check_app_falls_back_when_the_page_cannot_attach(monkeypatch, fake_web):
    red = _FakeRedirector(attach_ok=False)
    res, seen = _check_app(monkeypatch, fake_web, red)
    assert seen["url"] == "http://example.com/" and red.exited.wait(5)


def test_check_app_does_not_wait_for_a_stalled_docker(monkeypatch, fake_web):
    red = _FakeRedirector()
    t = time.monotonic()
    res, seen = _check_app(monkeypatch, fake_web, red, delay=3.0, wait=0.2)
    assert seen["url"] == "http://example.com/" and red.attached is None
    assert red.exited.wait(10)  # removed once its start finishes


def test_missing_preview_still_fails_r18_with_egress(fake_web):
    res = _run(fake_web, http_proxy="http://127.0.0.1:9")
    assert [r.id for r in res.failures] == ["R18"]


def test_feedback_never_asks_to_undo_hardening(fake_web):
    # Even when the app fails, the repair prompt must not demand integer ids or a
    # byte-identical upload, and never shows an unresolved id ("None").
    res = _run(fake_web, ID_MODE="uuid", IMG_MODE="reencode", SLOW_SECONDS=0, AVATAR_MODE="badurl")
    text = feedback(res)
    assert "None" not in text and "동일" not in text and "같은 파일" not in text
    assert "재인코딩해도 됨" in text  # R25 fails here: the prompt allows re-encoding


def test_deadline_bounds_the_whole_run(fake_web):
    # A slow app (0.3 s per request, ~190 requests) must not hold the check past the
    # generation budget (review 10).
    t0 = time.monotonic()
    res = _run(fake_web, deadline=time.monotonic() + 2.0, SLOW_SECONDS=0.3)
    assert time.monotonic() - t0 < 6
    assert not res.ok and res.total == 32


def test_check_app_falls_back_when_the_page_name_does_not_resolve(monkeypatch, fake_web):
    red = _FakeRedirector()
    res, seen = _check_app(monkeypatch, fake_web, red, unreachable=("http://11.137.0.9/page",))
    assert seen["urls"] == ["http://11.137.0.9/page", "http://example.com/"]
    assert red.exited.wait(5)


@pytest.mark.parametrize("box_kw", [{"boot_failed": True}, {"infra_error": True}])
def test_check_app_removes_the_page_when_the_app_does_not_boot(monkeypatch, fake_web, box_kw):
    red = _FakeRedirector()
    try:
        _check_app(monkeypatch, fake_web, red, box_kw=box_kw)
    except RuntimeError:
        pass
    assert red.exited.wait(5)
