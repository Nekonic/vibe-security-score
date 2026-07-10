"""Auto-imported (on PYTHONPATH): force any generated Flask app to bind
0.0.0.0:APP_PORT (reachable via Docker's port map) with the reloader off.
Generated apps often use `app.run(debug=True)` which binds 127.0.0.1."""
import os

try:
    import flask

    _orig_run = flask.Flask.run
    _port = int(os.environ.get("APP_PORT", "5000"))

    def _run(self, host=None, port=None, *args, **kwargs):
        kwargs["use_reloader"] = False  # keep other kwargs (e.g. debug) so vulns still score
        return _orig_run(self, "0.0.0.0", _port, *args, **kwargs)

    flask.Flask.run = _run
except Exception:
    pass
