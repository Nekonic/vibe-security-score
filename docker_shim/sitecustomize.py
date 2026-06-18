"""Grader container shim — auto-imported at interpreter startup via PYTHONPATH.

Python's site initialization imports a module named ``sitecustomize`` if one is
importable. The grader mounts this directory read-only into the submission
container and puts it on PYTHONPATH, so this runs before the app's own code.

Purpose: force any Flask app started with ``app.run()`` to bind
``0.0.0.0:<port>`` with the reloader disabled. Vibe-coded apps frequently call
``app.run()`` (Flask default host 127.0.0.1), which is unreachable through Docker
published ports — the container's loopback is not the host's. Rebinding to
0.0.0.0 makes the app reachable on every platform (Linux and Docker Desktop).

Apps started via the ``flask run`` CLI already honour the grader's
``--host``/``--port`` and are unaffected. The shim never raises into the app.
"""
import os

_PORT = int(os.environ.get("GRADER_APP_PORT", "5000"))

try:
    import flask

    _orig_run = flask.Flask.run

    def _patched_run(self, *args, **kwargs):
        # Drop any host/port the app passed (positional or keyword) and force ours.
        kwargs.pop("host", None)
        kwargs.pop("port", None)
        kwargs["use_reloader"] = False  # reloader forks; avoid in the container
        return _orig_run(self, "0.0.0.0", _PORT, **kwargs)

    flask.Flask.run = _patched_run
except Exception:
    # If Flask isn't importable for any reason, leave the app untouched.
    pass
