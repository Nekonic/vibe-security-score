"""LiveServer: runs a snapshot of the workdir on its own port, restarts on change."""
from __future__ import annotations

import os
import pathlib
import time

import pytest
import requests

from codex_runner.live import LiveServer
from codex_runner.runner import _free_port

pytest.importorskip("flask")
pytestmark = pytest.mark.skipif(os.name == "nt", reason="live preview is POSIX-only")

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
_APP = (
    "from flask import Flask\n"
    "app = Flask(__name__)\n"
    "open('app.db', 'w').write('x')\n"   # runtime state must stay in the snapshot
    "@app.route('/')\n"
    "def index():\n"
    "    return {body!r}\n"
    "if __name__ == '__main__':\n"
    "    app.run()\n"
)


def _wait_for(port, text, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(f"http://127.0.0.1:{port}/", timeout=1)
            if text in r.text:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.3)
    return False


def test_serves_snapshot_and_restarts_on_change(tmp_path):
    env = dict(os.environ, PYTHONPATH=str(_REPO_ROOT / "sandbox"))
    port = _free_port()
    live = LiveServer(tmp_path, port, env, poll_seconds=0.3).start()
    try:
        (tmp_path / "app.py").write_text(_APP.format(body="first"), encoding="utf-8")
        assert _wait_for(port, "first")
        (tmp_path / "app.py").write_text(_APP.format(body="second"), encoding="utf-8")
        assert _wait_for(port, "second")
        assert not (tmp_path / "app.db").exists()  # ran from the snapshot, not the workdir
    finally:
        live.stop()
    with pytest.raises(requests.RequestException):
        requests.get(f"http://127.0.0.1:{port}/", timeout=1)
