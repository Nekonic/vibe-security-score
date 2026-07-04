#!/bin/sh
# Inside the sandbox: pip-install the participant's requirements (non-fatal on
# failure — the boot/functional gate decides), then boot the Flask app.
set -u

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR" || exit 97

if [ -f requirements.txt ]; then
    # --user keeps installs in the unprivileged user's site-packages.
    pip install --user --no-warn-script-location -r requirements.txt \
        || echo "[sandbox] pip install failed (continuing to boot attempt)" >&2
fi

# Prefer an app factory / module named app.py exposing `app`.
if [ -f app.py ]; then
    exec python app.py
elif [ -f wsgi.py ]; then
    exec python wsgi.py
elif [ -f main.py ]; then
    exec python main.py
else
    echo "[sandbox] no app.py/wsgi.py/main.py found" >&2
    exit 98
fi
