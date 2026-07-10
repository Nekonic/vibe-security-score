"""Live-activity stream for the generation phase.

The codex JSONL events are operator-internal and leak host paths / temp workdirs.
This module turns each raw event into a **redacted, participant-safe activity
item** and persists it line-by-line to ``events.jsonl`` so the web UI can tail it
in real time (read-only). Redaction happens ONCE here, in the trusted worker, so
the Django endpoint can serve the file verbatim.
"""
from __future__ import annotations

import json
import pathlib
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# The generation workdir is a temp dir named ``codexgen_{id}_{rand}``; strip that
# prefix everywhere so only project-relative paths ever reach a participant.
_REL_AFTER_WORKDIR = re.compile(r"/codexgen_[^/]*/(?P<rel>.*)$")
_WORKDIR_PREFIX = re.compile(r"[^\s'\"]*/codexgen_[^/\s'\"]*/")


def _redact(text: str) -> str:
    """Remove absolute temp-workdir prefixes from free text (commands, messages)."""
    if not text:
        return text
    return _WORKDIR_PREFIX.sub("", text)


def _rel_path(path: str) -> str:
    """Project-relative path for a file_change entry (drops the temp workdir)."""
    if not path:
        return path
    m = _REL_AFTER_WORKDIR.search(path)
    if m:
        return m.group("rel")
    return pathlib.PurePath(path).name


def to_activity(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Normalize a raw codex event into a redacted UI activity item, or None to
    drop it (low-signal lifecycle events)."""
    et = event.get("type")
    if et == "thread.started":
        return {"kind": "status", "text": "세션 시작"}
    if et == "turn.completed":
        return {"kind": "status", "text": "생성 완료"}
    if et == "error":
        return {"kind": "status", "text": "오류 발생"}
    if et != "item.completed":
        return None  # drop turn.started / item.started noise

    item = event.get("item", {}) or {}
    it = item.get("type")
    if it == "agent_message":
        text = _redact(str(item.get("text", "")).strip())
        return {"kind": "message", "text": text} if text else None
    if it == "command_execution":
        # Command only (no aggregated_output — it can echo host paths/secrets).
        cmd = _redact(str(item.get("command", "")).strip())
        return {"kind": "command", "command": cmd, "exit_code": item.get("exit_code")} if cmd else None
    if it == "file_change":
        files = [
            {"path": _rel_path(str(c.get("path", ""))), "kind": str(c.get("kind", ""))}
            for c in (item.get("changes", []) or [])
        ]
        return {"kind": "files", "files": files} if files else None
    return None


def events_path(config, submission_id: str) -> pathlib.Path:
    """Location of the live activity log for a submission (``events.jsonl``). Single
    source used by both the writer and the reader. Kept in its own tree
    (``codex.events_dir``), SEPARATE from the operator-only ``transcript.json``
    (``codex.transcript_dir``), so the redacted participant log and the raw
    transcript never mix.

    ``config`` may be None (the orchestrator passes its ``scoring_config`` which is
    None unless explicitly set) — default to the loaded config like generate/grade
    do, so the sink never silently no-ops."""
    if config is None:
        from scoring.config import load_config
        config = load_config()
    tmpl = config.get("codex.events_dir", "data/generation_events/{submission_id}")
    dir_str = str(tmpl).replace("{submission_id}", str(submission_id))
    p = pathlib.Path(dir_str)
    if not p.is_absolute():
        p = _REPO_ROOT / p
    return p / "events.jsonl"


def open_sink(config, submission_id: str) -> Tuple[Callable[[Dict[str, Any]], None], pathlib.Path]:
    """Truncate the events file and return a ``sink(raw_event)`` that appends the
    redacted activity item and flushes it (so the web can tail live)."""
    path = events_path(config, submission_id)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")  # fresh per run
    except OSError:
        pass

    def sink(event: Dict[str, Any]) -> None:
        item = to_activity(event)
        if item is None:
            return
        try:
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(item, ensure_ascii=False) + "\n")
                fh.flush()
        except OSError:
            pass

    return sink, path


def read_activity(config, submission_id: str) -> List[Dict[str, Any]]:
    """All activity items written so far. Tolerates a partially-written last line
    (the writer may be mid-append)."""
    path = events_path(config, submission_id)
    out: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return out
    return out


__all__ = ["to_activity", "events_path", "open_sink", "read_activity"]