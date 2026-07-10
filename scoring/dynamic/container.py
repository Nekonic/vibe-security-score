"""Sandbox container lifecycle for the dynamic phase.

``Sandbox`` is a context manager that stages the app into an ASCII temp path
(Docker Desktop bind-mounts of the Korean OneDrive path are unreliable), docker
runs the prebuilt image with config resource limits (network STAYS ON), polls
boot, and tears everything down on exit. All docker calls use argv lists (no
shell) so Git-Bash path mangling does not apply.
"""
from __future__ import annotations

import os
import sys
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from typing import List, Optional

import urllib.error
import urllib.request

from ..config import Config

_STAGE_EXCLUDE = {"__pycache__", ".git", ".venv", "venv", ".mypy_cache", ".pytest_cache"}


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _stage_app_dir(app_dir: str) -> str:
    """Copy ``app_dir`` into a fresh ASCII temp directory; return that path."""
    base = os.environ.get("VIBE_SEC_STAGE_DIR")
    if not base and sys.platform == "darwin":
        base = "/tmp"
    stage_root = tempfile.mkdtemp(prefix="vibe_sec_stage_", dir=base)
    stage_app = os.path.join(stage_root, "app")

    def _ignore(_dir: str, names: List[str]) -> List[str]:
        return [n for n in names if n in _STAGE_EXCLUDE or n.endswith(".pyc")]

    shutil.copytree(app_dir, stage_app, ignore=_ignore)
    return stage_root


class Sandbox:
    def __init__(self, app_dir: str, config: Config):
        self.app_dir = app_dir
        self.config = config
        self.image = str(config.get("sandbox.image", "vibe-sec-sandbox:latest"))
        self.app_port = int(config.get("sandbox.app_port", 5000))
        self.memory = str(config.get("sandbox.memory", "512m"))
        self.cpus = str(config.get("sandbox.cpus", "1.0"))
        self.pids_limit = int(config.get("sandbox.pids_limit", 256))
        self.run_as_uid = int(config.get("sandbox.run_as_uid", 10001))
        self.boot_timeout = float(config.get("timeouts.app_boot", 45))

        self.container_name = f"vibe-sec-dyn-{uuid.uuid4().hex[:12]}"
        self.host_port = _find_free_port()
        self.base_url = f"http://127.0.0.1:{self.host_port}"

        self._stage_root: Optional[str] = None
        self._started = False
        self.boot_failed = False
        self._mount_src: Optional[str] = None

    def __enter__(self) -> "Sandbox":
        try:
            mount_src = os.path.abspath(self.app_dir)
            # 마운트 소스 검증: 진입점 파일이 실제로 있는지 확인 (없으면 즉시 boot 실패 처리)
            if not any(os.path.isfile(os.path.join(mount_src, f))
                       for f in ("app.py", "wsgi.py", "main.py")):
                raise RuntimeError(
                    f"no app.py/wsgi.py/main.py in {mount_src}"
                )
            self._mount_src = mount_src
            self._docker_run(mount_src)
            self._started = True
            if not self._wait_for_boot():
                self.boot_failed = True
        except Exception:
            self.boot_failed = True
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._teardown()
        return False  # never swallow exceptions

    def _docker_run(self, mount_src: str) -> None:
        argv = [
            "docker", "run", "-d",
            "--name", self.container_name,
            "-p", f"{self.host_port}:{self.app_port}",
            "-e", "APP_DIR=/app",
            "-e", "DATABASE=/work/app.db",
            "-v", f"{mount_src}:/app:ro",
            "--tmpfs", f"/work:rw,size=128m,uid={self.run_as_uid}",
            "--tmpfs", f"/tmp:rw,size=64m,uid={self.run_as_uid}",
            "--memory", self.memory,
            "--cpus", self.cpus,
            "--pids-limit", str(self.pids_limit),
            # NETWORK STAYS ON — never --network none.
            self.image,
        ]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            raise RuntimeError(
                f"docker run failed: {proc.stderr.strip() or proc.stdout.strip()}"
            )

    def _wait_for_boot(self) -> bool:
        """Poll GET /posts until it answers (any status) or app_boot elapses."""
        url = f"{self.base_url}/posts"
        deadline = time.monotonic() + self.boot_timeout
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3) as resp:
                    if resp.status:
                        return True
            except urllib.error.HTTPError:
                return True  # server answered => booted
            except (urllib.error.URLError, OSError, ConnectionError):
                pass
            if not self._container_running():
                return False
            time.sleep(0.5)
        return False

    def _container_running(self) -> bool:
        try:
            proc = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", self.container_name],
                capture_output=True, text=True, timeout=15,
            )
            return proc.returncode == 0 and proc.stdout.strip() == "true"
        except Exception:
            return False

    def pip_freeze(self) -> str:
        """Resolved (transitive) package versions actually installed in the running
        container — `name==version` per line. Empty string if unavailable. This is
        what makes the AI's dependency *choice* (incl. transitive deps) scorable."""
        for py in ("python", "python3"):
            try:
                proc = subprocess.run(
                    ["docker", "exec", self.container_name, py, "-m", "pip", "freeze"],
                    capture_output=True, text=True, timeout=30,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return proc.stdout
            except Exception:
                continue
        return ""

    def logs(self, tail: int = 40) -> str:
        try:
            proc = subprocess.run(
                ["docker", "logs", "--tail", str(tail), self.container_name],
                capture_output=True, text=True, timeout=15,
            )
            return (proc.stdout or "") + (proc.stderr or "")
        except Exception:
            return ""

    def _teardown(self) -> None:
        try:
            subprocess.run(
                ["docker", "rm", "-f", self.container_name],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            pass
        self._started = False