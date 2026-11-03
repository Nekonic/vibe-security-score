"""Runner tests, driven by ``fake_codex.py`` (no real codex CLI needed)."""
from __future__ import annotations

import copy
import glob
import json
import os
import pathlib
import re
import sys

import pytest

from scoring.config import Config, load_config

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
    raw["codex"]["events_dir"] = str(tmp_path / "events" / "{submission_id}")
    raw["codex"]["workdir_base"] = str(tmp_path / "gen")
    raw.setdefault("timeouts", {})
    raw["timeouts"]["codex_exec"] = timeout
    # The contract loop boots the app in Docker; loop tests inject a fake check.
    raw["codex"]["contract_loop"] = {"enabled": False, "min_round_seconds": 0, "check_retries": 2}
    cfg = Config(raw)
    _GEN_BASE["base"] = tmp_path / "gen"
    os.environ["FAKE_CODEX_MODE"] = mode
    return cfg


@pytest.fixture(autouse=True)
def _clean_mode_env():
    yield
    os.environ.pop("FAKE_CODEX_MODE", None)


@pytest.fixture(autouse=True)
def _deps_builds(monkeypatch):
    """No real deps image build: record which harvested dirs would get one."""
    built = []
    monkeypatch.setattr("codex_runner.runner._build_deps",
                        lambda outdir, _cfg: built.append((outdir / "requirements.txt").read_text()))
    return built


_GEN_BASE = {}


def _count_codexgen_workdirs() -> int:
    """Workdirs left under THIS test's own workdir_base (never the shared temp dir)."""
    base = _GEN_BASE.get("base")
    return len(glob.glob(os.path.join(str(base), "codexgen_*"))) if base else 0


def test_success_harvests_project_and_writes_prompt(tmp_path):
    cfg = _make_config("success", tmp_path=tmp_path)
    before = _count_codexgen_workdirs()

    outdir = generate("sub_success", _PARTICIPANT_PROMPT, config=cfg)

    assert outdir.is_dir()
    assert (outdir / "app.py").is_file()
    assert (outdir / "requirements.txt").is_file()
    assert (outdir / "templates" / "base.html").is_file()

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
    generate("sub_scrub2", _PARTICIPANT_PROMPT, config=cfg, keep_workdir=True)
    matches = sorted(
        (tmp_path / "gen").glob("codexgen_sub_scrub2_*/_env_seen.json")
    )
    assert matches, "fake_codex did not write _env_seen.json"
    seen = json.loads(matches[-1].read_text(encoding="utf-8"))
    assert not seen.get("OPENAI_API_KEY"), seen
    assert not seen.get("CODEX_API_KEY"), seen

    import shutil
    shutil.rmtree(matches[-1].parent, ignore_errors=True)
    assert outdir.is_dir()


def test_self_test_server_gets_its_own_port_for_live_preview(tmp_path):
    from codex_runner.activity import read_preview_port

    cfg = _make_config("success", tmp_path=tmp_path)
    outdir = generate("sub_port", _PARTICIPANT_PROMPT, config=cfg, keep_workdir=True)
    env_file = sorted((tmp_path / "gen").glob("codexgen_sub_port_*/_env_seen.json"))[-1]
    seen = json.loads(env_file.read_text(encoding="utf-8"))

    port = seen["APP_PORT"]
    assert port and port.isdigit() and seen["APP_HOST"] == "127.0.0.1"
    assert seen["PYTHONPATH"].split(os.pathsep)[0] == str(_REPO_ROOT / "sandbox")
    assert f"http://127.0.0.1:{port}" in seen["stdin"]          # model told where to test
    assert "상대 경로" in seen["stdin"]                          # ...and to stay in its folder
    assert env_file.parent.parent == tmp_path / "gen"            # workdir under workdir_base
    assert (outdir / "prompt.md").read_text(encoding="utf-8") == _PARTICIPANT_PROMPT
    assert read_preview_port(cfg, "sub_port") is None            # cleared once done

    import shutil
    shutil.rmtree(env_file.parent, ignore_errors=True)


def test_ratelimit_raises_with_retry_after(tmp_path):
    cfg = _make_config("ratelimit", tmp_path=tmp_path)
    before = _count_codexgen_workdirs()

    with pytest.raises(errors.RateLimitError) as ei:
        generate("sub_rl", _PARTICIPANT_PROMPT, config=cfg)

    assert ei.value.retry_after > 0
    assert _count_codexgen_workdirs() == before


def test_failed_command_with_429_not_misread_as_ratelimit(tmp_path):
    # A failed self-test command whose output contains HTTP 429 / 'rate limit' is the
    # generated app's own code, NOT a Codex rate limit. Generation must SUCCEED, not
    # raise RateLimitError and re-queue forever (regression: transcript #26).
    cfg = _make_config("noisy_ok", tmp_path=tmp_path)
    outdir = generate("sub_noisy", _PARTICIPANT_PROMPT, config=cfg)
    assert (outdir / "app.py").is_file()
    tpath = tmp_path / "transcripts" / "sub_noisy" / "transcript.json"
    data = json.loads(tpath.read_text(encoding="utf-8"))
    assert data["outcome"] == "success"


def test_timeout_raises_and_leaves_no_child(tmp_path):
    cfg = _make_config("timeout", timeout=2.0, tmp_path=tmp_path)
    before = _count_codexgen_workdirs()

    with pytest.raises(errors.GenerationTimeoutError):
        generate("sub_to", _PARTICIPANT_PROMPT, config=cfg)

    assert _count_codexgen_workdirs() == before

    # No lingering workdir = tree kill + cleanup worked (Windows would fail if held open).
    leftover = list(
        (tmp_path / "gen").glob("codexgen_sub_to_*")
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


from codex_runner import runner as _runner_mod  # noqa: E402


def test_binary_argv_posix_resolved(monkeypatch):
    cfg = Config({"codex": {"binary": "codex"}})
    monkeypatch.setattr(_runner_mod, "_IS_WINDOWS", False)
    monkeypatch.setattr(_runner_mod.shutil, "which", lambda b: "/usr/local/bin/codex")
    assert _runner_mod._binary_argv(cfg) == ["/usr/local/bin/codex"]




# ── contract loop ──────────────────────────────────────────────────────────
from scoring.contract import ContractResult, Requirement  # noqa: E402


def _result(failed_ids):
    reqs = [Requirement(f"R{i:02d}", f"req {i}", f"R{i:02d}" not in failed_ids,
                        "GET /x", "2xx", "" if f"R{i:02d}" not in failed_ids else "404")
            for i in range(1, 6)]
    return ContractResult(booted=True, requirements=reqs)


def _resume_seen(outdir):
    # each fake repair appends "# ROUNDS = n" to the harvested requirements.txt
    p = outdir / "requirements.txt"
    rounds = re.findall(r"^# (ROUNDS = \d+)$", p.read_text(encoding="utf-8"), re.M) if p.exists() else []
    return rounds[-1] + "\n" if rounds else ""


def test_contract_loop_resumes_same_session_until_pass(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    sessions = tmp_path / "codex_home" / "sessions" / "2026" / "10" / "25"
    sessions.mkdir(parents=True)
    rollout = sessions / "rollout-2026-0f0f0f0f-fake-thread.jsonl"
    rollout.write_text("{}", encoding="utf-8")
    cfg = _make_config("success", tmp_path=tmp_path)
    results = iter([_result({"R02", "R04"}), _result({"R04"}), _result(set())])
    checked = []

    def check(outdir):
        checked.append(_resume_seen(outdir))
        return next(results)

    outdir = generate("sub_loop", _PARTICIPANT_PROMPT, config=cfg, contract_check=check)

    # build + 2 repairs, each re-checked on the freshly harvested project
    assert checked == ["", "ROUNDS = 1\n", "ROUNDS = 2\n"]
    transcript = json.loads((tmp_path / "transcripts" / "sub_loop" / "transcript.json").read_text(encoding="utf-8"))
    assert [r["failed"] for r in transcript["contract"]] == [["R02", "R04"], ["R04"], []]
    assert "resume" not in transcript["argv"]  # the recorded argv is the build's
    assert not rollout.exists(), "session rollout must be deleted after the loop"
    assert (outdir / "prompt.md").read_text(encoding="utf-8") == _PARTICIPANT_PROMPT


def test_contract_loop_feedback_names_failures_and_resumes_thread(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path)
    results = iter([_result({"R03"}), _result(set())])
    seen_workdirs = []

    def check(outdir):
        seen_workdirs.append(outdir)
        return next(results)

    generate("sub_fb", _PARTICIPANT_PROMPT, config=cfg, keep_workdir=True, contract_check=check)

    assert len(seen_workdirs) == 2  # build + one repair that passes
    workdir = next(pathlib.Path(_GEN_BASE["base"]).glob("codexgen_sub_fb_*"))
    log = json.loads((workdir / "_resume_seen.json").read_text(encoding="utf-8"))
    assert len(log) == 1
    assert "resume" in log[0]["argv"] and "0f0f0f0f-fake-thread" in log[0]["argv"]
    assert "[R03]" in log[0]["stdin"] and "404" in log[0]["stdin"]
    assert "req 1" not in log[0]["stdin"]  # passing requirements are not echoed


def test_deps_image_is_built_after_harvest_and_after_each_repair(tmp_path, monkeypatch, _deps_builds):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path)
    results = iter([_result({"R01"}), _result(set())])
    seen = []

    def check(outdir):
        seen.append(len(_deps_builds))  # the image is there before the box boots
        return next(results)

    generate("sub_deps", _PARTICIPANT_PROMPT, config=cfg, contract_check=check)
    assert seen == [1, 2] and all(_deps_builds)


def test_contract_loop_stops_when_first_build_passes(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path)
    calls = []
    generate("sub_ok", _PARTICIPANT_PROMPT, config=cfg,
             contract_check=lambda d: calls.append(d) or _result(set()))
    assert len(calls) == 1


def _transcript(tmp_path, sid):
    return json.loads((tmp_path / "transcripts" / sid / "transcript.json").read_text(encoding="utf-8"))


def _broken(outdir) -> bool:
    app = outdir / "app.py"
    return not app.exists() or "def broken(" in app.read_text(encoding="utf-8")


def test_contract_loop_keeps_repairing_past_two_rounds(tmp_path, monkeypatch):
    # No round cap: Codex is asked again until the app passes (TASKS item 2).
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path)
    results = iter([_result({"R01"})] * 4 + [_result(set())])
    outdir = generate("sub_many", _PARTICIPANT_PROMPT, config=cfg, contract_check=lambda d: next(results))
    assert _resume_seen(outdir) == "ROUNDS = 4\n"
    assert [r["passed"] for r in _transcript(tmp_path, "sub_many")["contract"]] == [4, 4, 4, 4, 5]


def test_contract_never_passing_is_a_generation_failure_not_graded(tmp_path, monkeypatch):
    # The budget runs out before 30/30: ContractFailedError, nothing left to grade.
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path, timeout=3)
    calls = []
    with pytest.raises(errors.ContractFailedError) as exc:
        generate("sub_never", _PARTICIPANT_PROMPT, config=cfg,
                 contract_check=lambda d: calls.append(d) or _result({"R02"}))
    assert len(calls) > 2, "it must keep asking for repairs while there is budget"
    assert "(" not in str(exc.value)
    assert not (tmp_path / "generated" / "sub_never").exists(), "a failing build must not stay for grading"
    tx = _transcript(tmp_path, "sub_never")
    assert tx["outcome"] == "contract_failed" and tx["contract"][-1]["failed"] == ["R02"]


def test_contract_loop_min_round_seconds_stops_early(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path, timeout=30)
    cfg.raw["codex"]["contract_loop"]["min_round_seconds"] = 30  # never that much left
    calls = []
    with pytest.raises(errors.ContractFailedError):
        generate("sub_min", _PARTICIPANT_PROMPT, config=cfg,
                 contract_check=lambda d: calls.append(d) or _result({"R02"}))
    assert len(calls) == 1


def test_repair_that_breaks_the_app_is_repaired_again_never_graded(tmp_path, monkeypatch):
    # Review 9: a repair that breaks the project is re-checked (boot failure goes back
    # as feedback) and repaired again; only the passing build is returned.
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    monkeypatch.setenv("FAKE_CODEX_RESUME", "break,delete,fix")
    cfg = _make_config("success", tmp_path=tmp_path)
    seen = []

    def check(outdir):
        seen.append(_broken(outdir))
        if _broken(outdir):
            return ContractResult(booted=False, boot_log="SyntaxError: invalid syntax")
        return _result({"R02"}) if len(seen) == 1 else _result(set())

    outdir = generate("sub_break", _PARTICIPANT_PROMPT, config=cfg, keep_workdir=True, contract_check=check)
    assert seen == [False, True, True, False]
    assert not _broken(outdir)
    workdir = next(pathlib.Path(_GEN_BASE["base"]).glob("codexgen_sub_break_*"))
    log = json.loads((workdir / "_resume_seen.json").read_text(encoding="utf-8"))
    assert "SyntaxError" in log[1]["stdin"], "the boot failure is fed back to Codex"


def test_slow_contract_check_counts_against_the_budget(tmp_path, monkeypatch):
    # Review 10: a check that outlives timeouts.codex_exec must not extend generation.
    import time

    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path, timeout=3)
    t0 = time.monotonic()
    with pytest.raises(errors.ContractFailedError):
        generate("sub_slow", _PARTICIPANT_PROMPT, config=cfg,
                 contract_check=lambda d: time.sleep(8) or _result(set()))
    assert time.monotonic() - t0 < 5


def test_timeout_after_thread_started_drops_session_rollout(tmp_path, monkeypatch):
    # Review 11: the first run times out after the session started; its rollout (the
    # participant's prompt) must still be deleted.
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("timeout_after_thread", tmp_path=tmp_path, timeout=3)
    with pytest.raises(errors.GenerationTimeoutError):
        generate("sub_to", _PARTICIPANT_PROMPT, config=cfg)
    assert not list((tmp_path / "codex_home" / "sessions").glob("**/*0f0f0f0f-fake-thread*"))


def test_sandbox_error_rechecks_the_same_build(tmp_path, monkeypatch):
    from scoring.shared.sandbox import SandboxError

    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path)
    outcomes = iter([SandboxError("docker run failed"), _result(set())])
    calls = []

    def check(outdir):
        calls.append(outdir)
        o = next(outcomes)
        if isinstance(o, Exception):
            raise o
        return o

    outdir = generate("sub_sbx", _PARTICIPANT_PROMPT, config=cfg, contract_check=check)
    assert len(calls) == 2 and _resume_seen(outdir) == "", "same build re-checked, no repair asked"


def test_persistent_check_error_is_bounded_and_not_a_contract_failure(tmp_path, monkeypatch):
    # Review 12: a crash in the check (docker trouble or a suite bug) is not the app's
    # fault: bounded re-checks, then a plain (retryable) GenerationError.
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    cfg = _make_config("success", tmp_path=tmp_path)
    calls = []

    def check(outdir):
        calls.append(outdir)
        raise AttributeError("'int' object has no attribute 'startswith'")

    with pytest.raises(errors.GenerationError) as exc:
        generate("sub_crash", _PARTICIPANT_PROMPT, config=cfg, contract_check=check)
    assert not isinstance(exc.value, errors.ContractFailedError)
    assert len(calls) == 3  # first check + check_retries=2
    assert _transcript(tmp_path, "sub_crash")["outcome"] == "check_error"


def test_rate_limit_during_repair_requeues(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex_home"))
    monkeypatch.setenv("FAKE_CODEX_RESUME", "ratelimit")
    cfg = _make_config("success", tmp_path=tmp_path)
    with pytest.raises(errors.RateLimitError):
        generate("sub_rl", _PARTICIPANT_PROMPT, config=cfg, contract_check=lambda d: _result({"R01"}))
    assert not (tmp_path / "generated" / "sub_rl").exists()


# ── shipped front end (TASKS item 5) ───────────────────────────────────────
_SEED = _REPO_ROOT / "codex_runner" / "seed"


def _seed_files():
    return sorted(p.relative_to(_SEED) for p in _SEED.rglob("*") if p.is_file())


def _assert_seed_front_end(outdir):
    for rel in _seed_files():
        assert (outdir / rel).read_bytes() == (_SEED / rel).read_bytes(), rel
    assert (outdir / "static" / "uploads").is_dir()


def test_seed_is_in_the_workdir_before_codex_runs(tmp_path):
    cfg = _make_config("success", tmp_path=tmp_path)
    generate("sub_seed", _PARTICIPANT_PROMPT, config=cfg, keep_workdir=True)
    workdir = next(pathlib.Path(_GEN_BASE["base"]).glob("codexgen_sub_seed_*"))
    seen = json.loads((workdir / "_seed_seen.json").read_text(encoding="utf-8"))
    assert seen and all(seen.values()), seen


def test_front_end_is_harvested_as_codex_left_it(tmp_path):
    cfg = _make_config("success", tmp_path=tmp_path)
    outdir = generate("sub_only", _PARTICIPANT_PROMPT, config=cfg)
    # fake codex edited templates/base.html and static/board.js and added a template:
    # nothing overwrites them, the contract's hash check is what sends them back
    assert "|safe" in (outdir / "templates" / "base.html").read_text(encoding="utf-8")
    assert (outdir / "templates" / "index.html").exists()
    assert (outdir / "static" / "uploads").is_dir()
    # extra .py modules are still dropped
    assert not (outdir / "helpers.py").exists()
    assert sorted(p.name for p in outdir.glob("*.py")) == ["app.py"]


def test_seed_hash_check_flags_edits_and_passes_the_seed(tmp_path):
    from scoring.config import load_config
    from scoring.contract import seed_unchanged
    config = load_config()
    app = tmp_path / "app"
    for rel in _seed_files():
        (app / rel).parent.mkdir(parents=True, exist_ok=True)
        (app / rel).write_bytes((_SEED / rel).read_bytes())
    (app / "static" / "uploads").mkdir(parents=True, exist_ok=True)
    (app / "static" / "uploads" / "x.png").write_bytes(b"png")
    assert seed_unchanged(str(app), config).passed
    (app / "templates" / "base.html").write_text("{{ x|safe }}", encoding="utf-8")
    (app / "templates" / "index.html").write_text("new", encoding="utf-8")
    r = seed_unchanged(str(app), config)
    assert not r.passed
    assert "templates/base.html 바뀜" in r.actual and "templates/index.html 추가됨" in r.actual
