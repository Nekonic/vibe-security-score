"""Live app preview: one sandbox container per submission, so a logged-in user can
open the generated app in the browser (reverse-proxied by ``preview_views``).

Unlike the PoC console, state is NOT held in this process: gunicorn runs several
workers and any of them may serve the next request. Docker itself is the session
table — the container is named ``<prefix><pk>`` and its published port is read back
with ``docker port`` — and a per-submission stamp file's mtime records last use for
the idle reaper. Every docker path is best-effort and never raises out.
"""
from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Tuple

import requests

from django.conf import settings
from scoring.config import load_config
from scoring.shared.sandbox import Sandbox

# Per-process cache of pk -> (host_port, checked_at), so a page with many assets
# doesn't shell out to `docker port` per request.
_PORT_TTL = 10.0
_PORTS: Dict[int, Tuple[int, float]] = {}
_REAP_EVERY = 30.0
_last_reap = 0.0
_LOCK = threading.Lock()


def _cfg():
    return load_config()


def _opt(cfg, key, default):
    return cfg.get(f"preview.{key}", default)


def container_name(pk: int, cfg=None) -> str:
    cfg = cfg or _cfg()
    return f"{_opt(cfg, 'container_prefix', 'vibe-sec-preview-')}{pk}"


def _state_dir(cfg) -> Path:
    d = Path(str(_opt(cfg, "state_dir", "data/preview_sessions")))
    if not d.is_absolute():
        d = Path(settings.REPO_ROOT) / d
    d.mkdir(parents=True, exist_ok=True)
    return d


def touch(pk: int, cfg=None) -> None:
    try:
        (_state_dir(cfg or _cfg()) / str(pk)).touch()
    except OSError:
        pass


def answers(port: int, timeout: float = 1.0) -> bool:
    """True once an HTTP server answers on ``port`` (any status). An HTTP request —
    not a bare TCP connect — because docker's port proxy accepts connections before
    the app inside is up."""
    try:
        requests.get(f"http://127.0.0.1:{port}/", timeout=timeout, allow_redirects=False)
        return True
    except requests.RequestException:
        return False


def wait_ready(pk: int, cfg=None):
    """Block until the preview container's app answers, up to ``timeouts.app_boot``.
    Returns its host port, or "exited" / "missing" / "timeout"."""
    cfg = cfg or _cfg()
    deadline = time.monotonic() + float(cfg.get("timeouts.app_boot", 45))
    while time.monotonic() < deadline:
        state = container_state(pk, cfg)
        if state != "running":
            return state
        port = host_port(pk, cfg)
        if port is not None and answers(port):
            return port
        time.sleep(0.5)
    return "timeout"


def _docker(*args: str, timeout: float = 15) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def container_state(pk: int, cfg=None) -> str:
    """'running' | 'exited' | 'missing' (docker unavailable counts as missing)."""
    try:
        proc = _docker("inspect", "-f", "{{.State.Running}}", container_name(pk, cfg))
    except Exception:
        return "missing"
    if proc.returncode != 0:
        return "missing"
    return "running" if proc.stdout.strip() == "true" else "exited"


def host_port(pk: int, cfg=None) -> Optional[int]:
    cfg = cfg or _cfg()
    now = time.time()
    with _LOCK:
        hit = _PORTS.get(pk)
        if hit and now - hit[1] < _PORT_TTL:
            return hit[0]
    try:
        proc = _docker("port", container_name(pk, cfg), str(cfg.get("sandbox.app_port", 5000)))
    except Exception:
        return None
    port = None
    for line in (proc.stdout or "").splitlines():
        tail = line.rsplit(":", 1)[-1].strip()
        if tail.isdigit():
            port = int(tail)
            break
    with _LOCK:
        if port is None:
            _PORTS.pop(pk, None)
        else:
            _PORTS[pk] = (port, now)
    return port


def cached_port(pk: int) -> Optional[int]:
    """The port ``host_port`` read from docker within the last ``_PORT_TTL`` s, or
    None. No docker call: the proxy forwards to it straight away and only goes
    back to docker when the app doesn't answer or the entry is stale."""
    with _LOCK:
        hit = _PORTS.get(pk)
    if hit and time.time() - hit[1] < _PORT_TTL:
        return hit[0]
    return None


def forget_port(pk: int) -> None:
    with _LOCK:
        _PORTS.pop(pk, None)


def logs(pk: int, tail: int = 30) -> str:
    try:
        proc = _docker("logs", "--tail", str(tail), container_name(pk))
        return (proc.stdout or "") + (proc.stderr or "")
    except Exception:
        return ""


def remove(pk: int) -> None:
    forget_port(pk)
    try:
        _docker("rm", "-f", container_name(pk), timeout=30)
    except Exception:
        pass


def _preview_names(cfg) -> list:
    prefix = str(_opt(cfg, "container_prefix", "vibe-sec-preview-"))
    try:
        proc = _docker("ps", "-a", "--filter", f"name={prefix}", "--format", "{{.Names}}")
    except Exception:
        return []
    return [n for n in (proc.stdout or "").split() if n.startswith(prefix)]


def reap_idle(force: bool = False) -> None:
    """Remove preview containers idle past ``idle_timeout_seconds`` (throttled)."""
    global _last_reap
    now = time.time()
    with _LOCK:
        if not force and now - _last_reap < _REAP_EVERY:
            return
        _last_reap = now
    cfg = _cfg()
    idle = float(_opt(cfg, "idle_timeout_seconds", 900))
    prefix = str(_opt(cfg, "container_prefix", "vibe-sec-preview-"))
    state = _state_dir(cfg)
    for name in _preview_names(cfg):
        pk = name[len(prefix):]
        try:
            last = (state / pk).stat().st_mtime
        except OSError:
            last = 0.0
        if now - last > idle and pk.isdigit():
            remove(int(pk))


def start(sub) -> dict:
    """Start the preview container for ``sub`` if it isn't there yet. Returns at once
    (``docker run -d``); the app keeps booting inside — see ``wait_ready``. Another
    worker winning the name race is fine."""
    cfg = _cfg()
    reap_idle(force=True)
    if container_state(sub.pk, cfg) != "missing":
        touch(sub.pk, cfg)
        return {"ok": True}
    limit = int(_opt(cfg, "max_containers", 8))
    if len(_preview_names(cfg)) >= limit:
        return {"ok": False, "error": f"미리보기 앱이 가득 찼어요(최대 {limit}개). 잠시 후 다시 시도해 주세요."}
    box = Sandbox(sub.workdir, cfg)
    box.container_name = container_name(sub.pk, cfg)
    touch(sub.pk, cfg)
    try:
        box._docker_run(os.path.abspath(sub.workdir))
    except Exception:
        if container_state(sub.pk, cfg) == "missing":  # not a lost name race
            return {"ok": False, "error": "미리보기 컨테이너를 시작하지 못했어요."}
    forget_port(sub.pk)
    return {"ok": True}
