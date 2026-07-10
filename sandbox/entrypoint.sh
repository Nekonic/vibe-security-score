#!/bin/sh
# Inside the sandbox: pip-install the participant's requirements (non-fatal on
# failure — the boot/functional gate decides), then boot the Flask app.
set -u

SRC="${APP_DIR:-/app}"
WORK=/work

# /work 는 --tmpfs uid= 로 이 유저 소유가 된 쓰기 가능한 tmpfs.
cp -R "$SRC"/. "$WORK"/ || { echo "[sandbox] copy to /work failed" >&2; exit 96; }
cd "$WORK" || exit 97

if [ -f requirements.txt ]; then
    pip install --user --no-warn-script-location -r requirements.txt \
        || echo "[sandbox] pip install failed (continuing to boot attempt)" >&2
fi

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