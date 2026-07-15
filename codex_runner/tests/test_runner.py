"""Runner tests, driven by ``fake_codex.py`` (no real codex CLI needed)."""
from __future__ import annotations

import copy
import glob
import json
import os
import pathlib
import sys
import tempfile

import pytest

from scoring.config import Config, load_config

import codex_runner
from codex_runner import errors
from codex_runner.runner import compute_backoff, generate

_HERE = pathlib.Path(__file__).resolve().parent
_FAKE = _HERE / "fake_codex.py"
_REPO_ROOT = _HERE.parent.parent

_PARTICIPANT_PROMPT = "게시판을 만들어줘. 비밀번호는 안전하게 저장해줘. SECRET-marker-12345"


def _make_config(mode: str, *, timeout: float = 30.0, tmp_path: pathlib.Path) -> Config:
    raw = copy.deepcopy(load_config().raw)
    raw.setdefault("codex", {})
    raw["codex"]["binary"] = [sys.executable, str(_FAKE)]
    raw["codex"]["output_base"] = str(tmp_path / "generated")
    raw["codex"]["transcript_dir"] = str(tmp_path / "transcripts" / "{submission_id}")
    raw.setdefault("timeouts", {})
    raw["timeouts"]["codex_exec"] = timeout
    cfg = Config(raw)
    os.environ["FAKE_CODEX_MODE"] = mode
    return cfg


@pytest.fixture(autouse=True)
def _clean_mode_env():
    yield
    os.environ.pop("FAKE_CODEX_MODE", None)


def _count_codexgen_workdirs() -> int:
    pattern = os.path.join(tempfile.gettempdir(), "codexgen_*")
    return len(glob.glob(pattern))


def test_success_harvests_project_and_writes_prompt(tmp_path):
    cfg = _make_config("success", tmp_path=tmp_path)
    before = _count_codexgen_workdirs()

    outdir = generate("sub_success", _PARTICIPANT_PROMPT, config=cfg)

    assert outdir.is_dir()
    assert (outdir / "app.py").is_file()
    assert (outdir / "requirements.txt").is_file()
    assert (outdir / "templates").is_dir()
    assert (outdir / "templates" / "index.html").is_file()

    prompt_md = outdir / "prompt.md"
    assert prompt_md.is_file()
    assert prompt_md.read_text(encoding="utf-8") == _PARTICIPANT_PROMPT

    assert _count_codexgen_workdirs() == before


def test_env_is_scrubbed_of_api_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-should-be-removed")
    monkeypatch.setenv("CODEX_API_KEY", "codex-should-be-removed")
    cfg = _make_config("success", tmp_path=tmp_path)

    outdir = generate("sub_scrub", _PARTICIPANT_PROMPT, config=cfg)

    # Re-run with keep_workdir so fake_codex's _env_seen.json survives for inspection.
    kept = generate("sub_scrub2", _PARTICIPANT_PROMPT, config=cfg, keep_workdir=True)
    matches = sorted(
        pathlib.Path(tempfile.gettempdir()).glob("codexgen_sub_scrub2_*/_env_seen.json")
    )
    assert matches, "fake_codex did not write _env_seen.json"
    seen = json.loads(matches[-1].read_text(encoding="utf-8"))
    assert not seen.get("OPENAI_API_KEY"), seen
    assert not seen.get("CODEX_API_KEY"), seen

    import shutil
    shutil.rmtree(matches[-1].parent, ignore_errors=True)
    assert outdir.is_dir()


def test_ratelimit_raises_with_retry_after(tmp_path):
    cfg = _make_config("ratelimit", tmp_path=tmp_path)
    before = _count_codexgen_workdirs()

    with pytest.raises(errors.RateLimitError) as ei:
        generate("sub_rl", _PARTICIPANT_PROMPT, config=cfg)

    assert ei.value.retry_after > 0
    assert _count_codexgen_workdirs() == before


def test_timeout_raises_and_leaves_no_child(tmp_path):
    cfg = _make_config("timeout", timeout=2.0, tmp_path=tmp_path)
    before = _count_codexgen_workdirs()

    with pytest.raises(errors.GenerationTimeoutError):
        generate("sub_to", _PARTICIPANT_PROMPT, config=cfg)

    assert _count_codexgen_workdirs() == before

    # No lingering workdir = tree kill + cleanup worked (Windows would fail if held open).
    leftover = list(
        pathlib.Path(tempfile.gettempdir()).glob("codexgen_sub_to_*")
    )
    assert not leftover, f"workdir/child lingered: {leftover}"


def test_fail_raises_generation_error(tmp_path):
    cfg = _make_config("fail", tmp_path=tmp_path)
    before = _count_codexgen_workdirs()

    with pytest.raises(errors.GenerationError):
        generate("sub_fail", _PARTICIPANT_PROMPT, config=cfg)

    assert _count_codexgen_workdirs() == before


def test_transcript_written_on_success(tmp_path):
    cfg = _make_config("success", tmp_path=tmp_path)
    generate("sub_tx", _PARTICIPANT_PROMPT, config=cfg)

    tpath = tmp_path / "transcripts" / "sub_tx" / "transcript.json"
    assert tpath.is_file()
    data = json.loads(tpath.read_text(encoding="utf-8"))
    assert data["outcome"] == "success"
    assert "app.py" in data["harvested"]
    assert _PARTICIPANT_PROMPT not in json.dumps(data["argv"])


def test_exception_str_is_generic(tmp_path):
    cfg = _make_config("ratelimit", tmp_path=tmp_path)
    with pytest.raises(errors.RateLimitError) as ei:
        generate("sub_generic", _PARTICIPANT_PROMPT, config=cfg)
    msg = str(ei.value)
    assert _PARTICIPANT_PROMPT not in msg
    assert "SECRET-marker-12345" not in msg
    tpath = tmp_path / "transcripts" / "sub_generic" / "transcript.json"
    assert tpath.is_file()


def test_compute_backoff_monotonic_and_capped():
    cfg = load_config()
    base = float(cfg.get("codex.rate_limit.backoff_base_seconds"))
    cap = float(cfg.get("codex.rate_limit.backoff_max_seconds"))

    values = [compute_backoff(a, cfg) for a in range(0, 20)]
    assert values[0] == base
    for a, b in zip(values, values[1:]):
        assert b >= a
    assert max(values) <= cap
    assert values[-1] == cap


def test_backoff_reexported_from_package():
    assert codex_runner.compute_backoff is compute_backoff


from codex_runner import runner as _runner_mod  # noqa: E402


def test_binary_argv_list_passthrough():
    cfg = Config({"codex": {"binary": ["python", "x.py"]}})
    assert _runner_mod._binary_argv(cfg) == ["python", "x.py"]


def test_binary_argv_windows_cmd_shim_runs_via_cmd(monkeypatch):
    cfg = Config({"codex": {"binary": "codex"}})
    monkeypatch.setattr(_runner_mod, "_IS_WINDOWS", True)
    monkeypatch.setattr(_runner_mod.shutil, "which", lambda b: r"C:\npm\codex.cmd")
    assert _runner_mod._binary_argv(cfg) == ["cmd", "/c", r"C:\npm\codex.cmd"]


def test_binary_argv_windows_exe_direct(monkeypatch):
    cfg = Config({"codex": {"binary": "codex"}})
    monkeypatch.setattr(_runner_mod, "_IS_WINDOWS", True)
    monkeypatch.setattr(_runner_mod.shutil, "which", lambda b: r"C:\codex\codex.exe")
    assert _runner_mod._binary_argv(cfg) == [r"C:\codex\codex.exe"]


def test_binary_argv_posix_resolved(monkeypatch):
    cfg = Config({"codex": {"binary": "codex"}})
    monkeypatch.setattr(_runner_mod, "_IS_WINDOWS", False)
    monkeypatch.setattr(_runner_mod.shutil, "which", lambda b: "/usr/local/bin/codex")
    assert _runner_mod._binary_argv(cfg) == ["/usr/local/bin/codex"]


def test_binary_argv_not_found_returns_raw_name(monkeypatch):
    cfg = Config({"codex": {"binary": "codex"}})
    monkeypatch.setattr(_runner_mod.shutil, "which", lambda b: None)
    assert _runner_mod._binary_argv(cfg) == ["codex"]
