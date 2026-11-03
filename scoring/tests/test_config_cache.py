"""load_config parses each file version once and hands every caller its own copy."""
from __future__ import annotations

import os

from scoring import config as config_mod
from scoring.config import load_config


def test_cached_parse_returns_independent_copies(tmp_path, monkeypatch):
    path = tmp_path / "s.yaml"
    path.write_text("dev: false\ncodex:\n  binary: codex\n", encoding="utf-8")
    calls = []
    real = config_mod.yaml.safe_load
    monkeypatch.setattr(config_mod.yaml, "safe_load", lambda fh: calls.append(1) or real(fh))

    a = load_config(str(path))
    a.dev = True
    a.raw["codex"]["binary"] = "fake"
    b = load_config(str(path))
    assert len(calls) == 1
    assert b is not a
    assert b.dev is False
    assert b.raw["codex"]["binary"] == "codex"


def test_reparses_when_file_changes(tmp_path):
    path = tmp_path / "s.yaml"
    path.write_text("dev: false\n", encoding="utf-8")
    assert load_config(str(path)).dev is False
    path.write_text("dev: true\n", encoding="utf-8")
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))
    assert load_config(str(path)).dev is True


def test_default_config_still_loads():
    cfg = load_config()
    assert cfg.get("efficiency.free_chars") is not None
