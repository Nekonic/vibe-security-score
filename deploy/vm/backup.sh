#!/bin/sh
# Daily copy of the grader DB and data (generated apps, transcripts) on the booth VM.
# sqlite's online backup gives a consistent copy while the web and worker run.
# Keeps 14 days in ~/backups.
set -eu
APP=/home/ubuntu/app
ROOT=/home/ubuntu/backups
# Folders are named in Korean time, as the README's dates are (the VM clock is UTC).
OUT=$ROOT/$(TZ=Asia/Seoul date +%Y%m%d-%H%M)
mkdir -p "$OUT"
"$APP/.venv/bin/python" -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close()" \
  "$APP/grader/db.sqlite3" "$OUT/db.sqlite3"
# GNU tar exits 1 when a file changed while it was read (the worker writes event
# logs during a run): the archive is still complete for every other file.
rc=0
tar -C "$APP" -czf "$OUT/data.tgz" --warning=no-file-changed --exclude=data/osv_db data || rc=$?
[ "$rc" -le 1 ] || exit "$rc"
find "$ROOT" -mindepth 1 -maxdepth 1 -type d -mtime +13 -exec rm -rf {} +
