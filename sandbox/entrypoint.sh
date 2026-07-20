#!/bin/sh
# Inside the sandbox: pip-install the participant's requirements (non-fatal on
# failure — the boot/functional gate decides), then boot the Flask app.
set -u

SRC="${APP_DIR:-/app}"
WORK=/work

# /work 는 --tmpfs uid= 로 이 유저 소유가 된 쓰기 가능한 tmpfs.
cp -R "$SRC"/. "$WORK"/ || { echo "[sandbox] copy to /work failed" >&2; exit 96; }

# 런타임 상태 파일 제거 — 매 채점을 clean state로 (앱은 부팅 시 init_db로 자기 DB를 새로 만듦)
find "$WORK" -type f \( -name '*.sqlite3' -o -name '*.sqlite' -o -name '*.db' \
  -o -name '*.db-journal' -o -name '*.db-wal' -o -name '*.db-shm' \) -delete 2>/dev/null || true

cd "$WORK" || exit 97

# 앱이 IMPORT 시점에 여는 관용 쓰기 디렉터리를 미리 만든다. 흔한 슬립: 모듈 최상위에서
# logging.FileHandler("logs/app.log") 를 열지만 os.makedirs 는 나중(main/init)에 실행 →
# 채점 tmpfs 는 빈 디렉터리를 harvest 하지 않아 FileNotFoundError 로 부팅 실패. 이 순서
# 슬립은 보안 신호가 아니므로, 미리 만들어 앱이 부팅돼 실제 보안 항목이 채점되게 한다.
mkdir -p logs log instance var/log 2>/dev/null || true

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