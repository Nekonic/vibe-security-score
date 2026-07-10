"""Gunicorn config for the vibe-security-score web UI / admin (production).

Run from the repo root:
    gunicorn -c deploy/gunicorn.conf.py core.wsgi:application

Only the web UI/admin runs under gunicorn. The submission pipeline runs in the
SEPARATE `run_worker` process (see deploy/systemd/). Gunicorn workers are
stateless here (submit + read), so multiple workers are fine with Postgres.
"""
import multiprocessing
import os

# chdir into the Django project dir so `core.wsgi` imports; settings.py adds
# the repo root to sys.path so the sibling scoring/ + codex_runner/ resolve.
chdir = os.environ.get("GRADER_DIR", "/opt/vibe-security-score/grader")

bind = os.environ.get("GUNICORN_BIND", "127.0.0.1:8001")
workers = int(os.environ.get("GUNICORN_WORKERS", (multiprocessing.cpu_count() * 2) + 1))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "60"))

# Log to stdout/stderr so systemd/journald captures it.
accesslog = "-"
errorlog = "-"
