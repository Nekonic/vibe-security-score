"""Kali-side replay of a graded probe: ``python <check_id>.py`` in ~/poc.

Runs the SAME scoring code the grade came from — ``scoring.engine.runner.run_probes``
with the same config and the same probe order — against a freshly restarted
``http://target:5000``. Every probe before the chosen one runs silently (they set up
the state the graded run had); the chosen one prints each HTTP exchange and its
verdict next to the stored grading result.

What a grading run has on the host — the app's logs, the SSRF callback listener and
its host addresses, the public redirector, a fresh target — the grader-side session
(grader/submissions/kali_session.py) serves over a token-protected control API.

Kali's ``python`` is the system one (its tools need it); this module re-runs the
script with the grader's venv python (/opt/vibe/.venv) before anything else, with
the venv's bin first on PATH for this process only.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request

VIBE_ROOT = "/opt/vibe"
VENV_BIN = VIBE_ROOT + "/.venv/bin"
VENV_PYTHON = VENV_BIN + "/python"
# Only for this replay process: the probes shell out to the grader's pinned sqlmap.
if os.path.isdir(VENV_BIN) and not os.environ.get("PATH", "").startswith(VENV_BIN + os.pathsep):
    os.environ["PATH"] = VENV_BIN + os.pathsep + os.environ.get("PATH", "")
if (sys.prefix != VIBE_ROOT + "/.venv" and os.path.exists(VENV_PYTHON)
        and sys.argv and sys.argv[0].endswith(".py")):
    os.execv(VENV_PYTHON, [VENV_PYTHON, *sys.argv])
sys.path.insert(0, VIBE_ROOT)

SESSION_FILE = "/root/poc/.session.json"
TARGET = "http://target:5000"
_BODY_MAX = 600


def _session() -> dict:
    with open(SESSION_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def _ctl(path: str, method: str = "GET", timeout: float = 180) -> str:
    s = _session()
    req = urllib.request.Request(s["control"] + path, method=method, headers={"X-Token": s["token"]})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


class RemoteCallback:
    """``ctx.ssrf_callback`` stand-in: the listener runs grader-side exactly as in a
    grading run; only the hit lookup goes over the control API."""

    def __init__(self, port: int):
        self.port = port

    def url_for(self, token: str, host: str) -> str:
        return f"http://{host}:{self.port}/{token}"

    def was_hit(self, token: str) -> bool:
        return _ctl("/hit?token=" + urllib.parse.quote(token)) == "1"


def _trace(on: list) -> None:
    """Print every requests exchange while ``on[0]`` is True."""
    import requests

    send = requests.Session.send

    def traced(self, request, **kw):
        resp = send(self, request, **kw)
        if on[0]:
            body = request.body.decode("utf-8", "replace") if isinstance(request.body, bytes) else (request.body or "")
            print(f"\n\033[36m> {request.method} {request.url}\033[0m")
            if body:
                print(f"  {body[:_BODY_MAX]}")
            print(f"\033[33m< {resp.status_code}\033[0m {resp.text[:_BODY_MAX].strip()}")
        return resp

    requests.Session.send = traced


def _context():
    from scoring.config import load_config
    from scoring.shared.http import DynamicContext

    s = _session()
    print(f"대상 앱 초기화 중... {TARGET}")
    _ctl("/reset", method="POST")

    config = load_config()
    ctx = DynamicContext(TARGET, config)
    ctx.app_logs = lambda: _ctl("/logs")
    if s.get("ssrf_port") and s.get("ssrf_hosts"):
        ctx.ssrf_callback = RemoteCallback(int(s["ssrf_port"]))
        ctx.ssrf_hosts = list(s["ssrf_hosts"])
        if s.get("redirector"):
            red = s["redirector"]
            ctx.ssrf_redirect = lambda target: f"http://{red}/r?to={urllib.parse.quote(target, safe='')}"
            from scoring.shared.ssrf_callback import PUBLIC_PAGE_MARKER
            ctx.ssrf_public_page = (f"http://{red}/page", PUBLIC_PAGE_MARKER)
    return ctx, config, s


def _deadline(config) -> float:
    """The grading run's whole-phase time budget, started the same way (after boot)."""
    import time
    return time.monotonic() + float(config.get("timeouts.dynamic_total", 180))


def _same(got, exp) -> bool:
    return ([round(got.score, 2), bool(got.passed), bool(got.skipped)]
            == [round(exp[0], 2), bool(exp[1]), bool(exp[2])])


def run_all() -> int:
    """Replay the whole probe sequence once and compare every check with the stored
    grade. Each check's prefix equals the one a single-check replay runs, so this
    verifies every ``<check>.py`` in one pass."""
    from scoring.engine.runner import run_probes

    ctx, config, s = _context()
    expected = s.get("expected") or {}
    bad = 0
    for got in run_probes(ctx, config, deadline=_deadline(config)):
        exp = expected.get(got.check_id)
        if exp is None:
            continue
        ok = _same(got, exp)
        bad += not ok
        print(f"{'일치' if ok else '다름'}  {got.check_id:26} {got.score:g}/{exp[0]:g}  "
              f"{got.passed}/{exp[1]}  {got.skipped}/{exp[2]}")
    print(json.dumps({"mismatch": bad}))
    return 1 if bad else 0


def run(check_id: str) -> int:
    from scoring.engine.runner import run_probes

    ctx, config, s = _context()
    on = [False]
    _trace(on)

    def before(c):
        on[0] = c.id == check_id
        if on[0]:
            print(f"\n\033[1m[{c.id}] {c.label}\033[0m")

    results = run_probes(ctx, config, deadline=_deadline(config), before=before, stop_after=check_id)
    on[0] = False
    got = results[-1]
    if got.check_id != check_id:
        print(f"\n알 수 없는 검사: {check_id}")
        return 2

    state = "판정 불가" if got.skipped else ("통과" if got.passed else "실패")
    print(f"\n\033[1m판정: {got.score:g}점 · {state}\033[0m")
    for reason in got.penalty_reasons:
        print(f"  - {reason}")

    exp = (s.get("expected") or {}).get(check_id)
    if exp is None:
        return 0
    if _same(got, exp):
        print("\033[32m채점 결과와 일치\033[0m")
        return 0
    print(f"\033[31m채점 결과와 다름 · 채점: {exp[0]:g}점 {'통과' if exp[1] else '실패'}{' 판정 불가' if exp[2] else ''}\033[0m")
    return 1


if __name__ == "__main__":
    sys.exit(run_all() if sys.argv[1] == "--all" else run(sys.argv[1]))
