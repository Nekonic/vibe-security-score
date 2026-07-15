"""In-process session manager for the operator attack-demonstration (PoC) console.

Model B (rendered-response, HTTP, no websockets). Per demo session:
  * ONE long-lived target container — the graded app, booted via
    ``scoring.shared.sandbox.Sandbox`` (kept alive between runs).
  * A disposable per-run attack container (``docker run --rm``) that executes the
    (possibly operator-edited) PoC in isolation and reaches the target at
    ``http://host.docker.internal:{host_port}``.

State lives in a module-level dict guarded by a lock. NOTE: this assumes a SINGLE
web process (fine for ``runserver`` / ``gunicorn --workers 1``); with multiple
workers each would hold its own session table and a start/run could hit different
workers. No DB model / migration is added by design.

Every docker / teardown path is best-effort and never raises out: a demo failure
must never crash the web process or leak containers.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

from django.conf import settings
from scoring.config import load_config
from scoring.shared.sandbox import Sandbox

_PLACEHOLDER_TARGET = "http://target:5000"
_ATTACK_HOST = "host.docker.internal"
# Repo root for resolving a Docker-shareable run_dir_base (the OS temp dir often
# isn't shared with the VM).
_REPO_ROOT = str(settings.REPO_ROOT)


@dataclass
class Session:
    box: Sandbox
    started_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)


_SESSIONS: Dict[int, Session] = {}
_LOCK = threading.Lock()


# --- config helpers ---------------------------------------------------------
def _cfg():
    return load_config()


def _poc_cfg(cfg, key, default):
    return cfg.get(f"poc.{key}", default)


def _run_dir_base(cfg) -> str:
    """Docker-shareable base dir for per-run PoC folders (see config note)."""
    base = str(_poc_cfg(cfg, "run_dir_base", "data/poc_runs"))
    if not os.path.isabs(base):
        base = os.path.join(_REPO_ROOT, base)
    try:
        os.makedirs(base, exist_ok=True)
    except Exception:
        base = tempfile.gettempdir()
    return base


# --- teardown / reaping -----------------------------------------------------
def _teardown(sess: Optional[Session]) -> None:
    if sess is None:
        return
    try:
        sess.box._teardown()
    except Exception:
        pass


def reap_idle() -> None:
    """Teardown sessions idle longer than ``poc.idle_timeout_seconds``.
    Caller need not hold the lock."""
    idle = float(_poc_cfg(_cfg(), "idle_timeout_seconds", 600))
    now = time.time()
    stale = []
    with _LOCK:
        for pk, sess in list(_SESSIONS.items()):
            if now - sess.last_used > idle:
                stale.append(_SESSIONS.pop(pk))
    for sess in stale:
        _teardown(sess)


# --- public API -------------------------------------------------------------
def start(sub) -> dict:
    """Boot (or refresh) the target container for ``sub``. Enforces the
    concurrent-session cap; returns a JSON-able status dict."""
    reap_idle()
    cfg = _cfg()
    max_sessions = int(_poc_cfg(cfg, "max_sessions", 4))

    with _LOCK:
        existing = _SESSIONS.get(sub.pk)
        if existing is not None:
            existing.last_used = time.time()
            return {"ok": True, "ready": True, "reused": True}
        if len(_SESSIONS) >= max_sessions:
            return {
                "ok": False,
                "error": f"동시 시연 세션이 가득 찼습니다(최대 {max_sessions}). 잠시 후 다시 시도하세요.",
            }

    box = Sandbox(sub.workdir, cfg)
    box.__enter__()  # boots + waits for boot
    if box.boot_failed:
        logs = ""
        try:
            logs = box.logs(tail=20)
        except Exception:
            logs = ""
        _teardown(Session(box=box))
        return {"ok": False, "error": "대상 앱 부팅 실패", "logs": logs}

    with _LOCK:
        # A racing start may have created one meanwhile; keep the first, drop ours.
        if sub.pk in _SESSIONS:
            existing = _SESSIONS[sub.pk]
            existing.last_used = time.time()
            loser = box
            box = None  # type: ignore
        else:
            _SESSIONS[sub.pk] = Session(box=box)
            loser = None
    if loser is not None:
        _teardown(Session(box=loser))
    return {"ok": True, "ready": True}


def run(sub, check_id: str, code: str) -> dict:
    """Run one PoC in a fresh disposable attack container against the live target.
    Returns stdout/stderr plus any HTML the PoC captured via ``render``."""
    reap_idle()
    with _LOCK:
        sess = _SESSIONS.get(sub.pk)
        if sess is None:
            return {"ok": False, "error": "세션이 없습니다. 먼저 세션을 시작하세요."}
        sess.last_used = time.time()
        host_port = sess.box.host_port

    cfg = _cfg()
    attack_image = str(_poc_cfg(cfg, "attack_image", "vibe-sec-attack:latest"))
    run_timeout = float(_poc_cfg(cfg, "run_timeout_seconds", 20))

    # Point the PoC at the real, live target container.
    real_target = f"http://{_ATTACK_HOST}:{host_port}"
    code = (code or "").replace(_PLACEHOLDER_TARGET, real_target)

    poc_dir = tempfile.mkdtemp(prefix="vibe-sec-poc-", dir=_run_dir_base(cfg))
    try:
        with open(os.path.join(poc_dir, "run.py"), "w", encoding="utf-8") as fh:
            fh.write(code)
        # mkdtemp is 0700; the attack container's non-root uid must traverse the
        # bind mount and write out.html back, so open it up (disposable dir).
        try:
            os.chmod(poc_dir, 0o777)
        except OSError:
            pass

        argv = [
            "docker", "run", "--rm",
            "--add-host", f"{_ATTACK_HOST}:host-gateway",
            "--network", "bridge",
            "--memory", "256m",
            "--cpus", "1.0",
            "--pids-limit", "128",
            "-v", f"{poc_dir}:/poc",
            "-e", "PYTHONPATH=/opt/poclib",
            attack_image,
            "python", "/poc/run.py",
        ]
        stdout, stderr, timed_out = "", "", False
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=run_timeout,
            )
            stdout, stderr = proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired as e:
            timed_out = True
            stdout = (e.stdout or b"").decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = (e.stderr or b"").decode(errors="replace") if isinstance(e.stderr, bytes) else (e.stderr or "")
            stderr = (stderr + f"\n[!] {run_timeout:.0f}s 시간 초과로 공격 컨테이너를 종료했습니다.").strip()
        except Exception as e:
            stderr = f"[!] 공격 컨테이너 실행 실패: {e}"

        html = ""
        out_path = os.path.join(poc_dir, "out.html")
        try:
            if os.path.isfile(out_path):
                with open(out_path, "r", encoding="utf-8", errors="replace") as fh:
                    html = fh.read()
        except Exception:
            html = ""

        with _LOCK:
            sess = _SESSIONS.get(sub.pk)
            if sess is not None:
                sess.last_used = time.time()

        return {"ok": True, "stdout": stdout, "stderr": stderr,
                "html": html, "timed_out": timed_out}
    finally:
        try:
            shutil.rmtree(poc_dir, ignore_errors=True)
        except Exception:
            pass


def stop(sub) -> dict:
    with _LOCK:
        sess = _SESSIONS.pop(sub.pk, None)
    _teardown(sess)
    return {"ok": True, "stopped": sess is not None}
