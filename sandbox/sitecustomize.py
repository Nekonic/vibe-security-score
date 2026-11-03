"""Auto-imported (on PYTHONPATH): force any generated Flask app to bind
APP_HOST:APP_PORT (default 0.0.0.0 — reachable via Docker's port map) with the
reloader off. Generated apps often use `app.run(debug=True)` which binds 127.0.0.1.
The Codex runner also loads this during generation (APP_HOST=127.0.0.1, a per-run
APP_PORT) so the self-test server can be shown live.

Also loads the harvested `.env` (cwd = /work) into os.environ, so an app that keeps
its SECRET_KEY etc. in .env boots the same way it did when self-tested — whether or
not it ships python-dotenv. Real environment variables win (setdefault)."""
import os


def _load_dotenv(path=".env"):
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        else:
            value = value.split(" #", 1)[0].rstrip()
        os.environ.setdefault(key, value)


_load_dotenv()

try:
    import flask

    _orig_run = flask.Flask.run
    _port = int(os.environ.get("APP_PORT", "5000"))

    def _run(self, host=None, port=None, *args, **kwargs):
        kwargs["use_reloader"] = False  # keep other kwargs (e.g. debug) so vulns still score
        # Force plain HTTP: some apps call app.run(ssl_context='adhoc') → the app serves
        # HTTPS while the grader probes http://…:PORT and reads it as a boot failure. TLS
        # isn't a scored dimension (transport_security judges headers/cookie flags), so
        # dropping it only makes the app reachable — it changes no security signal.
        kwargs.pop("ssl_context", None)
        return _orig_run(self, os.environ.get("APP_HOST", "0.0.0.0"), _port, *args, **kwargs)

    flask.Flask.run = _run
except Exception:
    pass
