"""Stand-in for the real ``codex exec`` binary. Behavior selected by
``FAKE_CODEX_MODE``: success / ratelimit / timeout / timeout_after_thread / fail.
Repair rounds (``resume``) follow ``FAKE_CODEX_RESUME``, a comma list used one item
per round (the last repeats): fix (default) / break (app.py no longer parses) /
delete (app.py removed) / ratelimit."""
from __future__ import annotations

import json
import os
import pathlib
import sys
import time


def _dump_env_seen(stdin_text: str = "") -> None:
    seen = {
        "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
        "CODEX_API_KEY": os.environ.get("CODEX_API_KEY"),
        "CODEX_HOME": os.environ.get("CODEX_HOME"),
        "APP_PORT": os.environ.get("APP_PORT"),
        "APP_HOST": os.environ.get("APP_HOST"),
        "PYTHONPATH": os.environ.get("PYTHONPATH"),
        "stdin": stdin_text,
    }
    with open("_env_seen.json", "w", encoding="utf-8") as fh:
        json.dump(seen, fh, ensure_ascii=False, indent=2)


FAKE_THREAD = "0f0f0f0f-fake-thread"


def main() -> int:
    mode = os.environ.get("FAKE_CODEX_MODE", "success")

    # Drain stdin so the parent's write/close completes (mirrors codex exec -).
    try:
        stdin_text = sys.stdin.read()
    except Exception:
        stdin_text = ""

    if mode == "timeout":
        time.sleep(3600)
        return 0

    if mode == "timeout_after_thread":
        # Like the real CLI: the session rollout exists as soon as the thread starts.
        print(json.dumps({"type": "thread.started", "thread_id": FAKE_THREAD}), flush=True)
        home = pathlib.Path(os.environ.get("CODEX_HOME") or (pathlib.Path.home() / ".codex"))
        d = home / "sessions" / "2026" / "10" / "30"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"rollout-2026-10-30T00-00-00-{FAKE_THREAD}.jsonl").write_text("{}\n", encoding="utf-8")
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

    if "resume" in sys.argv:
        # Repair round: record what the harness sent back, then "fix" the project.
        seen = []
        if os.path.exists("_resume_seen.json"):
            with open("_resume_seen.json", encoding="utf-8") as fh:
                seen = json.load(fh)
        seen.append({"argv": sys.argv[1:], "stdin": stdin_text})
        with open("_resume_seen.json", "w", encoding="utf-8") as fh:
            json.dump(seen, fh, ensure_ascii=False)
        plan = os.environ.get("FAKE_CODEX_RESUME", "fix").split(",")
        act = plan[min(len(seen), len(plan)) - 1]
        if act == "ratelimit":
            sys.stderr.write("Error: usage limit reached for this account.\n")
            return 1
        if act == "break":
            with open("app.py", "w", encoding="utf-8") as fh:
                fh.write("def broken(:\n    pass\n")
        elif act == "delete":
            os.remove("app.py")
        else:
            _write_project()
        # Round marker in a harvested file (extra .py modules are not harvested).
        with open("requirements.txt", "a", encoding="utf-8") as fh:
            fh.write(f"# ROUNDS = {len(seen)}\n")
        print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": "fixed"}}))
        sys.stdout.flush()
        return 0

    print(json.dumps({"type": "thread.started", "thread_id": FAKE_THREAD}))
    _dump_env_seen(stdin_text)
    _dump_seed_seen()
    _write_project()

    if mode == "noisy_ok":
        # A FAILED self-test command whose payload is the generated app's OWN code —
        # a board app that returns HTTP 429 / implements rate limiting. This must NOT
        # be read as a Codex rate limit (reproduces data/codex_transcripts/26).
        print(json.dumps({
            "type": "item.completed",
            "item": {
                "id": "item_9",
                "type": "command_execution",
                "status": "failed",
                "command": "python -c \"assert resp.status_code != 429  # rate limit guard\"",
                "aggregated_output": "AssertionError: too many requests -> 429 rate limit",
            },
        }))

    print(json.dumps({"type": "item.completed", "status": "success"}))
    sys.stdout.flush()
    return 0


SEED_PROBES = ("templates/base.html", "templates/post_detail.html",
               "static/board.js", "static/bootstrap.min.css", "static/uploads")


def _dump_seed_seen() -> None:
    """What the workdir held before this fake wrote anything (the shipped seed)."""
    with open("_seed_seen.json", "w", encoding="utf-8") as fh:
        json.dump({p: os.path.exists(p) for p in SEED_PROBES}, fh)


TAMPER = "<!-- codex edit -->{{ post.content|safe }}\n"


def _write_project() -> None:
    """app.py + requirements.txt, and the things the harvest must drop: an edited
    shipped template and static file, a new template, an extra .py module."""
    os.makedirs("templates", exist_ok=True)
    os.makedirs("static", exist_ok=True)
    with open(os.path.join("templates", "base.html"), "w", encoding="utf-8") as fh:
        fh.write(TAMPER)
    with open(os.path.join("static", "board.js"), "w", encoding="utf-8") as fh:
        fh.write("alert(1)\n")
    with open("helpers.py", "w", encoding="utf-8") as fh:
        fh.write("HELPER = 1\n")
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


if __name__ == "__main__":
    raise SystemExit(main())
