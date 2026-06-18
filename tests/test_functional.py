"""Regression tests for the functional gate — fully mocked, no Docker, no network.

We monkeypatch the docker/HTTP helper functions on the ``functional`` module so
that ``analyze()`` exercises the REAL scoring / gate / cleanup logic against
deterministic, simulated app behavior.
"""
import config
from modules import functional


# --------------------------------------------------------------------------- #
# Helpers                                                                       #
# --------------------------------------------------------------------------- #

def _patch_common(monkeypatch, cleanup_flag):
    """Patch docker available + start + cleanup (records cleanup call)."""
    monkeypatch.setattr(functional, "_docker_available", lambda: True)
    monkeypatch.setattr(functional, "_start_container", lambda *a, **k: None)
    # No real server in unit tests: CSRF fetch returns None (no token).
    monkeypatch.setattr(functional, "_fetch_csrf_token", lambda *a, **k: None)
    monkeypatch.setattr(
        functional, "_cleanup_container",
        lambda name: cleanup_flag.__setitem__("called", True))


def _finding(result, fid):
    for f in result["findings"]:
        if f["id"] == fid:
            return f
    return None


# --------------------------------------------------------------------------- #
# Scenario: Docker unavailable -> skipped, gate fails, cleanup not reached      #
# --------------------------------------------------------------------------- #

def test_docker_unavailable(monkeypatch, samples_dir):
    monkeypatch.setattr(functional, "_docker_available", lambda: False)
    res = functional.analyze(f"{samples_dir}/secure_app")
    assert res["score"] == 0
    assert res["gate_passed"] is False
    f = _finding(res, "docker_unavailable")
    assert f is not None and f.get("skipped") is True


# --------------------------------------------------------------------------- #
# Scenario: secure app — all three flows behave correctly                       #
# register/login succeed (200), wrong password rejected (401)                   #
# --------------------------------------------------------------------------- #

def test_secure_app_all_pass(monkeypatch, samples_dir):
    cleanup = {"called": False}
    _patch_common(monkeypatch, cleanup)
    monkeypatch.setattr(functional, "_wait_for_startup", lambda *a, **k: (True, "ok"))

    def fake_post(session, url, payload, csrf_token=None):
        # The wrong-password payload carries WRONG_PASSWORD among its values.
        if config.WRONG_PASSWORD in payload.values():
            return 401
        return 200

    monkeypatch.setattr(functional, "_post", fake_post)

    res = functional.analyze(f"{samples_dir}/secure_app")

    assert _finding(res, "register")["passed"] is True
    assert _finding(res, "login")["passed"] is True
    assert _finding(res, "reject_wrong_password")["passed"] is True
    assert res["score"] == float(sum(config.FUNCTIONAL_TEST_WEIGHTS.values()))  # 100
    assert res["gate_passed"] is True
    assert cleanup["called"] is True  # cleanup guaranteed


# --------------------------------------------------------------------------- #
# Scenario: insecure app — starts & logs in, but never rejects (returns 200)    #
# reject test fails; gate still passes on register+login                        #
# --------------------------------------------------------------------------- #

def test_insecure_app_no_rejection(monkeypatch, samples_dir):
    cleanup = {"called": False}
    _patch_common(monkeypatch, cleanup)
    monkeypatch.setattr(functional, "_wait_for_startup", lambda *a, **k: (True, "ok"))
    monkeypatch.setattr(functional, "_post", lambda *a, **k: 200)  # never rejects

    res = functional.analyze(f"{samples_dir}/insecure_app")

    assert _finding(res, "register")["passed"] is True
    assert _finding(res, "login")["passed"] is True
    assert _finding(res, "reject_wrong_password")["passed"] is False
    expected = float(config.FUNCTIONAL_TEST_WEIGHTS["register"]
                     + config.FUNCTIONAL_TEST_WEIGHTS["login"])
    assert res["score"] == expected  # 67
    assert res["gate_passed"] is True  # register + login passed
    assert cleanup["called"] is True


# --------------------------------------------------------------------------- #
# Scenario: broken app — fails to start (ImportError)                           #
# --------------------------------------------------------------------------- #

def test_broken_app_startup_fail(monkeypatch, samples_dir):
    cleanup = {"called": False}
    _patch_common(monkeypatch, cleanup)
    monkeypatch.setattr(
        functional, "_wait_for_startup",
        lambda *a, **k: (False, "ImportError: cannot import name 'nonexistent_helper'"))

    res = functional.analyze(f"{samples_dir}/broken_app")

    assert res["score"] == 0
    assert res["gate_passed"] is False
    startup = _finding(res, "app_startup")
    assert startup is not None and startup["passed"] is False
    assert "ImportError" in (startup["evidence"] or "")
    # The three tests are present as skipped because the app never came up.
    for fid in ("register", "login", "reject_wrong_password"):
        f = _finding(res, fid)
        assert f is not None and f.get("skipped") is True
    assert cleanup["called"] is True


# --------------------------------------------------------------------------- #
# Unit tests for the pure helpers                                               #
# --------------------------------------------------------------------------- #

def test_build_payload_maps_nonstandard_names():
    payload = functional._build_payload(
        config.TEST_USERNAME, config.TEST_PASSWORD, {"name", "pwd"})
    assert payload["name"] == config.TEST_USERNAME
    assert payload["pwd"] == config.TEST_PASSWORD
    # All configured aliases are always included. Aliases that also appear in
    # EMAIL_ALIASES (e.g. "email") are intentionally given the test email.
    for alias in config.USERNAME_ALIASES:
        if alias in config.EMAIL_ALIASES:
            continue
        assert payload[alias] == config.TEST_USERNAME
    for alias in config.PASSWORD_ALIASES:
        assert payload[alias] == config.TEST_PASSWORD
    for alias in config.EMAIL_ALIASES:
        assert payload[alias] == functional._TEST_EMAIL


def test_extract_field_names_insecure(samples_dir):
    names = functional._extract_field_names(f"{samples_dir}/insecure_app")
    assert "name" in names
    assert "pwd" in names


def test_status_helpers():
    assert functional._is_success_status(200) is True
    assert functional._is_success_status(302) is True
    assert functional._is_success_status(404) is False
    assert functional._is_reject_status(401) is True
    assert functional._is_reject_status(200) is False


def test_discover_entrypoint_insecure(samples_dir):
    entry, module = functional._discover_entrypoint(f"{samples_dir}/insecure_app")
    assert entry == "app.py"
    assert module == "app"


# --------------------------------------------------------------------------- #
# CSRF handling                                                                 #
# --------------------------------------------------------------------------- #

class _FakeResp:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code


def test_fetch_csrf_token_from_hidden_input():
    html = ('<form><input type="hidden" name="csrf_token" value="abc123">'
            '<input name="username"></form>')

    class S:
        cookies = []  # _declassify_cookies iterates this

        def get(self, url, **k):
            return _FakeResp(html)

    assert functional._fetch_csrf_token(S(), "http://x/register") == "abc123"


def test_fetch_csrf_token_none_when_absent():
    class S:
        cookies = []

        def get(self, url, **k):
            return _FakeResp("<form><input name='username'></form>")

    assert functional._fetch_csrf_token(S(), "http://x/register") is None


def test_post_attaches_csrf_field_and_header():
    captured = {}

    class S:
        cookies = []

        def post(self, url, **kwargs):
            captured.clear()
            captured.update(kwargs)
            return _FakeResp(status_code=200)

    functional._post(S(), "http://x/login", {"username": "u"}, csrf_token="tok")
    # The final (form) attempt carries the token as a field and as a header.
    assert captured["data"].get("csrf_token") == "tok"
    assert any(captured["headers"].get(h) == "tok" for h in config.CSRF_HEADER_NAMES)
