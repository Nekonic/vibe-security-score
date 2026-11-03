"""Live preview while Codex is generating.

Codex's own self-test servers only live for a few seconds, so the web can't rely on
them to show the app taking shape. ``LiveServer`` runs the app itself, on its own
port, from a *snapshot* of the workdir (so its DB/uploads never touch the files
Codex is testing against) and restarts it whenever the code changes.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
from typing import Dict, Optional, Tuple

_SKIP_DIRS = {".venv", "venv", "__pycache__", ".git", "node_modules"}
_SKIP_SUFFIXES = (".pyc", ".db", ".sqlite", ".sqlite3", ".log", "-journal", "-wal", "-shm")


def _skipped(rel: pathlib.PurePath) -> bool:
    return bool(_SKIP_DIRS.intersection(rel.parts)) or rel.name.endswith(_SKIP_SUFFIXES)


class LiveServer:
    def __init__(self, workdir: pathlib.Path, port: int, env: Dict[str, str],
                 poll_seconds: float = 1.0):
        self.workdir = pathlib.Path(workdir)
        self.port = port
        self.env = dict(env, APP_PORT=str(port), APP_HOST="127.0.0.1")
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._proc: Optional[subprocess.Popen] = None
        self._snapshot: Optional[pathlib.Path] = None

    def start(self) -> "LiveServer":
        if os.name == "nt":  # booth hosts are Linux/macOS
            return self
        self._thread = threading.Thread(target=self._loop, name="codex-live", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._kill()
        if self._snapshot is not None:
            shutil.rmtree(self._snapshot, ignore_errors=True)

    # -- internals -----------------------------------------------------------
    def _signature(self) -> Optional[Tuple]:
        """What the running app is built from; None until there is an app.py."""
        if not (self.workdir / "app.py").is_file():
            return None
        sig = []
        for path in self.workdir.rglob("*"):
            rel = path.relative_to(self.workdir)
            if path.is_file() and not _skipped(rel):
                try:
                    st = path.stat()
                except OSError:
                    continue
                sig.append((str(rel), st.st_mtime_ns, st.st_size))
        return tuple(sorted(sig))

    def _loop(self) -> None:
        running, pending = None, None
        while not self._stop.wait(self.poll_seconds):
            try:
                sig = self._signature()
                if sig is None or sig == running:
                    continue
                if sig != pending:  # let a burst of edits settle for one poll
                    pending = sig
                    continue
                running = sig
                self._restart()
            except Exception:
                continue  # a preview hiccup must never affect generation

    def _restart(self) -> None:
        self._kill()
        if self._snapshot is not None:
            shutil.rmtree(self._snapshot, ignore_errors=True)
        self._snapshot = pathlib.Path(tempfile.mkdtemp(prefix="codexlive_"))
        shutil.copytree(
            self.workdir, self._snapshot, dirs_exist_ok=True,
            ignore=lambda d, names: [n for n in names if _skipped(pathlib.PurePath(n))],
        )
        venv_python = self.workdir / ".venv" / "bin" / "python"
        python = str(venv_python) if venv_python.exists() else sys.executable
        self._proc = subprocess.Popen(
            [python, "app.py"], cwd=str(self._snapshot), env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

    def _kill(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
