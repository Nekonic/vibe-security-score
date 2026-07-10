"""Activity-stream redaction + persistence tests.

Replays a REAL captured transcript through the normalizer and asserts the
participant-facing output leaks no host paths, and that the write/read round-trip
+ live streaming from ``generate`` work.
"""
from __future__ import annotations

import json
import os

import pytest

from codex_runner import activity
from codex_runner.runner import generate
from scoring.config import load_config

_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
_TRANSCRIPT = os.path.join(_REPO_ROOT, "data", "codex_transcripts", "12", "transcript.json")


def _raw_events():
    with open(_TRANSCRIPT, encoding="utf-8") as fh:
        return json.load(fh)["events"]


pytestmark = pytest.mark.skipif(
    not os.path.isfile(_TRANSCRIPT), reason="sample transcript 12 not present"
)


def test_to_activity_redacts_host_paths():
    items = [a for e in _raw_events() if (a := activity.to_activity(e))]
    assert items, "expected some activity items from the transcript"
    blob = json.dumps(items, ensure_ascii=False)
    # No temp workdir / host path may reach a participant.
    for leak in ("/codexgen_", "/private/var", "/Users/", "/home/", "/tmp/"):
        assert leak not in blob, f"host path leaked: {leak}"


def test_file_change_paths_are_project_relative():
    files = [a for e in _raw_events() if (a := activity.to_activity(e)) and a["kind"] == "files"]
    assert files, "transcript 12 has a file_change event"
    paths = [f["path"] for grp in files for f in grp["files"]]
    assert "app.py" in paths
    assert any(p.startswith("templates/") for p in paths)
    assert all(not p.startswith("/") for p in paths)  # never absolute


def test_kinds_are_bounded():
    kinds = {a["kind"] for e in _raw_events() if (a := activity.to_activity(e))}
    assert kinds <= {"message", "command", "files", "status"}


def test_sink_write_read_roundtrip(tmp_path, monkeypatch):
    cfg = load_config()
    monkeypatch.setattr(
        activity, "events_path",
        lambda config, sid: tmp_path / str(sid) / "events.jsonl",
    )
    sink, path = activity.open_sink(cfg, "42")
    for e in _raw_events():
        sink(e)
    items = activity.read_activity(cfg, "42")
    assert items and path.exists()
    assert [i["kind"] for i in items][:1] == ["status"]  # thread.started -> status


def test_config_none_is_tolerated(tmp_path, monkeypatch):
    # The orchestrator passes scoring_config=None; open_sink/read_activity must NOT
    # silently no-op on it (regression: worker wrote no events because events_path
    # raised AttributeError on None and the pipeline swallowed it).
    monkeypatch.setattr(
        activity, "_REPO_ROOT", tmp_path,  # keep the write inside tmp
    )
    p = activity.events_path(None, "77")
    assert str(tmp_path) in str(p)
    sink, path = activity.open_sink(None, "77")
    sink({"type": "item.completed", "item": {"type": "agent_message", "text": "hi"}})
    items = activity.read_activity(None, "77")
    assert items == [{"kind": "message", "text": "hi"}]


def test_read_activity_tolerates_partial_last_line(tmp_path, monkeypatch):
    cfg = load_config()
    p = tmp_path / "9" / "events.jsonl"
    p.parent.mkdir(parents=True)
    p.write_text('{"kind":"message","text":"ok"}\n{"kind":"command"', encoding="utf-8")
    monkeypatch.setattr(activity, "events_path", lambda config, sid: p)
    items = activity.read_activity(cfg, "9")
    assert items == [{"kind": "message", "text": "ok"}]  # partial line skipped


# --- live streaming from generate() (fake codex binary) --------------------
_FAKE_CODEX = os.path.join(os.path.dirname(__file__), "fake_codex.py")


def test_generate_streams_events_to_sink(tmp_path):
    import sys

    cfg = load_config()
    cfg.raw["codex"] = dict(cfg.raw.get("codex", {}))
    cfg.raw["codex"]["binary"] = [sys.executable, _FAKE_CODEX]
    cfg.raw["codex"]["output_base"] = str(tmp_path / "gen")
    # Keep the transcript out of the real repo data dir (tmp, not data/…).
    cfg.raw["codex"]["transcript_dir"] = str(tmp_path / "tx" / "{submission_id}")

    seen = []
    generate("live1", "prompt", config=cfg, event_sink=lambda ev: seen.append(ev))
    # fake_codex emits a JSONL line => the sink saw at least one event live.
    assert any(isinstance(e, dict) and e.get("type") for e in seen)