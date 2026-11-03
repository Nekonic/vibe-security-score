"""Deps image per requirements set: the app's requirements are pip-installed once,
at image build, never when a container starts.

``vibe-sec-deps:<sha256(requirements.txt + base image id)[:16]>`` is built FROM the
sandbox image. codex_runner builds it right after harvest; an old app with no image
(regrade) gets it on first use. Docker's own image store is the cache, so a repair
that leaves requirements.txt alone builds nothing. A failed build is non-fatal: the
box runs the base image (Flask preinstalled) and the build log goes to the boot log.
App code is never baked in; Sandbox still mounts it read-only.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import threading
import time
from typing import Dict, Optional, Tuple

from ..config import Config

REPO = "vibe-sec-deps"

# --user as the image's runner, the same install the entrypoint used to do at start.
_DOCKERFILE = (
    "FROM {base}\n"
    "COPY requirements.txt /tmp/requirements.txt\n"
    "RUN pip install --user --no-warn-script-location -r /tmp/requirements.txt\n"
)

_lock = threading.Lock()
_tag_locks: Dict[str, threading.Lock] = {}
# Builds that failed in this process, with when: retrying each start would cost a
# full pip run, but a failure may be passing (PyPI down), so it is retried after
# ``_RETRY_AFTER`` seconds.
_failed: Dict[str, Tuple[float, str]] = {}
_RETRY_AFTER = 600.0


def _image_id(ref: str) -> Optional[str]:
    proc = subprocess.run(["docker", "image", "inspect", "-f", "{{.Id}}", ref],
                          capture_output=True, text=True, timeout=30)
    return (proc.stdout.strip() or None) if proc.returncode == 0 else None


def tag_for(requirements: bytes, base_id: str) -> str:
    return f"{REPO}:{hashlib.sha256(requirements + base_id.encode()).hexdigest()[:16]}"


def _build(tag: str, base: str, requirements: bytes, timeout: float) -> Tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="vibe-deps-") as ctx:
        with open(os.path.join(ctx, "Dockerfile"), "w", encoding="utf-8") as f:
            f.write(_DOCKERFILE.format(base=base))
        with open(os.path.join(ctx, "requirements.txt"), "wb") as f:
            f.write(requirements)
        try:
            proc = subprocess.run(["docker", "build", "--force-rm", "-t", tag, ctx],
                                  capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, f"의존성 이미지 빌드가 {timeout:g}초를 넘김"
    return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")


def ensure(app_dir: str, config: Config) -> Tuple[str, str]:
    """(image to run, build log). The log is non-empty only when the build failed and
    the base image is returned instead. Never raises."""
    base = str(config.get("sandbox.image", "vibe-sec-sandbox:latest"))
    req = os.path.join(app_dir, "requirements.txt")
    if not os.path.isfile(req):
        return base, ""
    try:
        with open(req, "rb") as f:
            requirements = f.read()
        base_id = _image_id(base)
        if not base_id:
            return base, ""  # docker run reports the missing base image
        tag = tag_for(requirements, base_id)
        with _lock:
            tag_lock = _tag_locks.setdefault(tag, threading.Lock())
        with tag_lock:  # one build per requirements set, however many boxes wait
            if tag in _failed and time.monotonic() - _failed[tag][0] < _RETRY_AFTER:
                return base, _failed[tag][1]
            if _image_id(tag):
                return tag, ""
            ok, log = _build(tag, base, requirements,
                             float(config.get("timeouts.container_build", 300)))
            if ok:
                _failed.pop(tag, None)
                return tag, ""
            _failed[tag] = (time.monotonic(), log.strip() or "의존성 이미지 빌드 실패")
            return base, _failed[tag][1]
    except Exception as exc:  # docker trouble: boot the base image, as a failed build
        return base, f"의존성 이미지 준비 실패: {exc}"
