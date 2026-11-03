"""Gunicorn config for the vibe-security-score web UI / admin (production).

Run from the repo root:
    gunicorn -c deploy/gunicorn.conf.py core.wsgi:application

Only the web UI/admin runs under gunicorn. The submission pipeline runs in the
SEPARATE `run_worker` process (see deploy/systemd/).

ONE worker process, many threads. The operator Kali console keeps its sessions (pty,
control server, SSRF listener) in the web process (grader/submissions/kali_session.py),
so every /kali/ request must reach the process that started the session; with
several workers they land on others and the console breaks. A booth's load (a few
laptops polling) fits one process; the long polls only wait, so threads are enough.
Do not raise `workers`.
"""
import os

# chdir into the Django project dir so `core.wsgi` imports; settings.py adds
# the repo root to sys.path so the sibling scoring/ + codex_runner/ resolve.
chdir = os.environ.get("GRADER_DIR", "/opt/vibe-security-score/grader")

bind = os.environ.get("GUNICORN_BIND", "127.0.0.1:8001")
workers = 1
worker_class = "gthread"
threads = int(os.environ.get("GUNICORN_THREADS", "32"))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "60"))

# Log to stdout/stderr so systemd/journald captures it.
accesslog = "-"
errorlog = "-"


def post_worker_init(worker):
    """Remove Kali containers a previous web process left, and start the reaper that
    removes a session once its page stops polling."""
    from submissions import kali_session
    kali_session.startup()
