"""Stand-in for the real ``codex exec`` binary. Behavior selected by
``FAKE_CODEX_MODE``: success / ratelimit / timeout / fail."""
from __future__ import annotations

import json
import os
import sys
import time


def _dump_env_seen() -> None:
    seen = {
        "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
        "CODEX_API_KEY": os.environ.get("CODEX_API_KEY"),
        "CODEX_HOME": os.environ.get("CODEX_HOME"),
    }
    with open("_env_seen.json", "w", encoding="utf-8") as fh:
        json.dump(seen, fh, ensure_ascii=False, indent=2)


def main() -> int:
    mode = os.environ.get("FAKE_CODEX_MODE", "success")

    # Drain stdin so the parent's write/close completes (mirrors codex exec -).
    try:
        _ = sys.stdin.read()
    except Exception:
        pass

    if mode == "timeout":
        time.sleep(3600)
        return 0

    if mode == "ratelimit":
        sys.stderr.write("Error: usage limit reached for this account.\n")
        sys.stderr.flush()
        return 1

    if mode == "fail":
        print(json.dumps({"type": "error", "message": "generation failed"}))
        sys.stdout.flush()
        return 2

    _dump_env_seen()

    os.makedirs("templates", exist_ok=True)
    with open("app.py", "w", encoding="utf-8") as fh:
        fh.write(
            "from flask import Flask\n"
            "app = Flask(__name__)\n\n"
            "@app.route('/')\n"
            "def index():\n"
            "    return 'ok'\n"
        )
    with open("requirements.txt", "w", encoding="utf-8") as fh:
        fh.write("flask\n")
    with open(os.path.join("templates", "index.html"), "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><title>board</title>\n")

    print(json.dumps({"type": "item.completed", "status": "success"}))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
