"""Sandbox container lifecycle for the dynamic phase.

``Sandbox`` is a context manager that bind-mounts the app dir read-only, docker
runs the prebuilt image with config resource limits (network STAYS ON), polls
boot, and tears everything down on exit. All docker calls use argv lists (no
shell) so Git-Bash path mangling does not apply.
"""
from __future__ import annotations

import os
import socket
import subprocess
import time
import uuid
from typing import Optional

import urllib.error
import urllib.request

from ..config import Config


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


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

        self.boot_failed = False

    def __enter__(self) -> "Sandbox":
        try:
            mount_src = os.path.abspath(self.app_dir)
            # 마운트 소스 검증: 진입점 파일이 실제로 있는지 확인 (없으면 즉시 boot 실패 처리)
            if not any(os.path.isfile(os.path.join(mount_src, f))
                       for f in ("app.py", "wsgi.py", "main.py")):
                raise RuntimeError(
                    f"no app.py/wsgi.py/main.py in {mount_src}"
                )
            self._docker_run(mount_src)
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
            # Let the container reach a grader listener on the host (SSRF callback).
            # host-gateway resolves to the bridge gateway (a PRIVATE range) — exactly
            # the kind of address a proper SSRF filter must block.
            "--add-host", "host.docker.internal:host-gateway",
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

    def host_gateway(self) -> Optional[str]:
        """The bridge gateway IP the container uses to reach the host — the address a
        grader-side SSRF callback listener is reachable at from inside the app. ``None``
        if it can't be resolved (then the live SSRF probe skips → static fallback)."""
        try:
            proc = subprocess.run(
                ["docker", "inspect", "-f",
                 "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", self.container_name],
                capture_output=True, text=True, timeout=15,
            )
            ip = (proc.stdout or "").strip()
            return ip or None
        except Exception:
            return None

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