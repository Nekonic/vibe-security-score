"""Codex runner: drive ``codex exec`` to generate a Flask project."""
from __future__ import annotations

import json
import logging
import os
import pathlib
import queue
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from scoring.config import Config, load_config

from .errors import (
    CodexRunnerError,
    ContractFailedError,
    GenerationError,
    GenerationTimeoutError,
    RateLimitError,
)

_IS_WINDOWS = os.name == "nt"
_log = logging.getLogger(__name__)
_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_DEFAULT_OUTPUT_BASE = "data/generated"


def compute_backoff(attempt: int, config: Config) -> float:
    """Exponential backoff ``base * 2**attempt`` capped at ``max`` (seconds)."""
    base = float(config.get("codex.rate_limit.backoff_base_seconds", 30))
    cap = float(config.get("codex.rate_limit.backoff_max_seconds", 3600))
    attempt = max(0, int(attempt))
    try:
        value = base * (2 ** attempt)
    except OverflowError:
        value = cap
    return float(min(value, cap))


def _binary_argv(config: Config) -> List[str]:
    binary = config.get("codex.binary", "codex")
    if isinstance(binary, (list, tuple)):
        return [str(x) for x in binary]

    binary = str(binary)
    resolved = shutil.which(binary)
    if resolved is None:
        return [binary]
    # npm installs codex as a .cmd shim on Windows; CreateProcess can't run it directly.
    if _IS_WINDOWS and resolved.lower().endswith((".cmd", ".bat")):
        return ["cmd", "/c", resolved]
    return [resolved]


def _build_argv(
    config: Config,
    model_override: Optional[str] = None,
    reasoning_override: Optional[str] = None,
    resume_id: Optional[str] = None,
) -> List[str]:
    """``codex exec`` argv, or ``codex exec resume <resume_id>`` for a repair round
    (same session, same workdir). ``resume`` has no --sandbox flag, so a non-bypass
    sandbox is passed as a config override there."""
    sandbox = config.get("codex.exec_flags.sandbox", "workspace-write")
    bypass = bool(config.get("codex.exec_flags.bypass_approvals", False))
    extra = config.get("codex.exec_flags.extra", []) or []
    # Admin (GraderSettings) wins when set; else fall back to config.
    model = model_override if model_override else (config.get("codex.model", "") or "")
    effort = reasoning_override if reasoning_override else (config.get("codex.reasoning_effort", "") or "")
    argv = [*_binary_argv(config), "exec"]
    if resume_id:
        argv.append("resume")
    # bypass_approvals => --dangerously-bypass-approvals-and-sandbox, which supersedes
    # (and is mutually exclusive with) --sandbox: it skips codex's approval gate too,
    # so exec doesn't auto-DENY destructive commands (rm -rf …) it can't prompt for.
    if bypass:
        argv.append("--dangerously-bypass-approvals-and-sandbox")
    elif resume_id:
        argv += ["-c", f'sandbox_mode="{sandbox}"']
    else:
        argv += ["--sandbox", str(sandbox)]
    argv += [str(f) for f in extra]
    # Omit --model when empty: ChatGPT-account auth rejects API-only ids like gpt-5-codex.
    if model:
        argv += ["--model", str(model)]
    # Reasoning effort has no dedicated exec flag; set it via the config override
    # (same key as ~/.codex/config.toml's model_reasoning_effort). Omit => model default.
    if effort:
        argv += ["-c", f"model_reasoning_effort={effort}"]
    if resume_id:
        argv.append(resume_id)
    argv += ["-"]  # prompt via stdin
    return argv


def _scrubbed_env(config: Config) -> Dict[str, str]:
    # Blank the API-key vars so generation uses the ChatGPT login only.
    env = dict(os.environ)
    for key in config.get("codex.blank_env", []) or []:
        env.pop(str(key), None)
    codex_home = config.get("codex.codex_home", None)
    if codex_home:
        env["CODEX_HOME"] = str(codex_home)
    # Extra env for the child (and the shell commands the model runs to self-test),
    # e.g. PIP_BREAK_SYSTEM_PACKAGES so `pip install` works on PEP 668 pythons.
    for key, value in (config.get("codex.child_env", {}) or {}).items():
        env[str(key)] = str(value)
    return env


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


# Appended to the prompt on stdin (not to prompt.md): each generation gets its own
# self-test port so parallel generations never collide on :5000, and the model is
# kept inside its own folder — weak models mangle long absolute paths, write files
# outside the workdir, then `find` and copy whatever app.py they come across
# (possibly another participant's).
# Appended by the harness to every first run: how to build and self-test in this
# environment. Not part of the participant-visible prompt (config/default_prompt.md).
_PORT_NOTE = (
    "\n\n## 작업 환경 안내\n"
    "- 이 환경에서 `app.run()`은 포트 인자와 상관없이 `http://127.0.0.1:{port}`에 뜬다. "
    "확인 요청은 이 주소로 보낸다.\n"
    "- 파일은 현재 폴더 안에 상대 경로로만 만든다. 현재 폴더 밖의 파일을 찾거나 복사하지 않는다.\n"
    "- 시스템 python에는 pip이 없고 `python` 실행파일도 없다. 아래처럼 uv로 설치하고 실행한다.\n"
    "  `uv venv .venv --allow-existing`, `uv pip install --python .venv -r requirements.txt`, "
    "`.venv/bin/python app.py`\n"
    "- `rm -rf`는 거절된다. 위 명령은 다시 실행해도 안전하다.\n"
    "- 고정한 Flask 버전에 실제로 있는 API만 쓴다. Flask 3에는 `flask.Markup`, `flask.escape`, "
    "`before_first_request`가 없다.\n"
    "- 서버가 떴는지 먼저 확인하고, 실제 HTTP 요청과 쿠키 세션으로 명세의 기능을 모두 돌려 본다. "
    "JSON과 form을 둘 다 쓴다. 응답이 `500`이거나 없으면 고친 뒤 처음부터 다시 돌린다.\n"
    "- 관측한 상태코드만 보고한다. 마지막 답에는 만든 파일과 확인한 요청, 상태코드만 짧게 적는다.\n"
)


def _workdir_base(config: Config) -> pathlib.Path:
    """Short, dedicated parent for generation workdirs (``codex.workdir_base``). A
    short path keeps the model from mangling it; a dedicated one keeps generation
    files out of the shared OS temp dir."""
    base = pathlib.Path(str(config.get("codex.workdir_base", "/tmp/vibegen")))
    if not base.is_absolute():
        base = _REPO_ROOT / base
    base.mkdir(parents=True, exist_ok=True)
    return base


def _self_test_env(env: Dict[str, str], port: int) -> None:
    """Route every Flask app started under codex through sandbox/sitecustomize.py (the
    same Flask.run patch the scoring sandbox uses), bound to 127.0.0.1:``port``."""
    boot = str(_REPO_ROOT / "sandbox")
    env["PYTHONPATH"] = os.pathsep.join(p for p in (boot, env.get("PYTHONPATH", "")) if p)
    env["APP_PORT"] = str(port)
    env["APP_HOST"] = "127.0.0.1"


def _rate_limit_signals(config: Config) -> List[str]:
    return [str(s).lower() for s in (config.get("codex.rate_limit.signals", []) or [])]


def _resolve_under_repo(path_str: str) -> pathlib.Path:
    p = pathlib.Path(path_str)
    if not p.is_absolute():
        p = _REPO_ROOT / p
    return p


def _popen_kwargs() -> Dict[str, Any]:
    if _IS_WINDOWS:
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        return {"creationflags": creationflags}
    return {"start_new_session": True}


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if _IS_WINDOWS:
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass
        try:
            proc.kill()
        except Exception:
            pass
    else:
        import signal

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def _kill_leftovers(proc: subprocess.Popen) -> None:
    """After codex exits, kill what it left running in its process group (the
    self-test app server) so it doesn't hold the port or outlive the workdir."""
    if _IS_WINDOWS:
        return
    import signal

    try:
        os.killpg(proc.pid, signal.SIGKILL)  # start_new_session => pgid == pid
    except Exception:
        pass


def _stream_reader(stream, tag: str, q: "queue.Queue") -> None:
    """Push (tag, line) for each line, then (tag, None) at EOF. Runs in a thread
    so stdout/stderr are drained concurrently (no pipe-buffer deadlock)."""
    try:
        for line in stream:
            q.put((tag, line))
    finally:
        q.put((tag, None))


def _run_codex(
    argv: Sequence[str],
    prompt: str,
    workdir: pathlib.Path,
    env: Dict[str, str],
    timeout: float,
    event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Tuple[int, str, str, float]:
    """Run codex, STREAMING stdout line-by-line so ``event_sink`` sees each JSONL
    event live (for the real-time UI). Still returns the full stdout/stderr for the
    transcript. stderr is drained in a thread; the wall-clock timeout kills the tree."""
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            list(argv),
            cwd=str(workdir),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,  # line-buffered so events arrive promptly
            **_popen_kwargs(),
        )
    except FileNotFoundError as exc:
        raise GenerationError(
            detail=(
                f"codex binary not found: {argv[0]!r} ({exc}). "
                "Install the Codex CLI and run `codex login`, or set codex.binary "
                "in config/scoring.yaml. Dev smoke: `python -m codex_runner.smoke`."
            )
        ) from exc

    # Feed the prompt then close stdin (codex exec reads the prompt from stdin).
    try:
        if proc.stdin is not None:
            proc.stdin.write(prompt)
            proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass

    q: "queue.Queue" = queue.Queue()
    threading.Thread(target=_stream_reader, args=(proc.stdout, "out", q), daemon=True).start()
    threading.Thread(target=_stream_reader, args=(proc.stderr, "err", q), daemon=True).start()

    stdout_parts: List[str] = []
    stderr_parts: List[str] = []
    eofs = 0
    deadline = start + timeout
    while eofs < 2:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _kill_tree(proc)
            elapsed = time.monotonic() - start
            raise GenerationTimeoutError(
                detail=f"codex exec exceeded {timeout}s (elapsed {elapsed:.1f}s)"
            )
        try:
            tag, line = q.get(timeout=min(1.0, remaining))
        except queue.Empty:
            continue
        if line is None:
            eofs += 1
            continue
        if tag == "out":
            stdout_parts.append(line)
            if event_sink is not None:
                obj = _parse_line(line)
                if obj is not None:
                    try:
                        event_sink(obj)
                    except Exception:
                        pass  # a bad sink must never break generation
        else:
            stderr_parts.append(line)

    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
    _kill_leftovers(proc)

    elapsed = time.monotonic() - start
    return (proc.returncode if proc.returncode is not None else -1,
            "".join(stdout_parts), "".join(stderr_parts), elapsed)


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    return obj if isinstance(obj, dict) else None


def _parse_jsonl(stdout: str) -> List[Dict[str, Any]]:
    return [obj for obj in map(_parse_line, stdout.splitlines()) if obj is not None]


# Item types whose payload is MODEL-controlled (shell commands the agent ran, files
# it wrote, and their output = the generated project). Their text legitimately
# contains '429', 'rate limit', etc., so it must NEVER feed rate-limit detection —
# even when the item FAILED. A failing self-test command is a generation problem, not
# a Codex rate limit. (See data/codex_transcripts/26: a failed command_execution whose
# app code contained HTTP 429 was misread as a 429 rate limit and re-queued forever.)
_MODEL_ITEM_TYPES = frozenset({
    "command_execution", "local_shell_call", "function_call", "custom_tool_call",
    "file_change", "patch_apply", "apply_patch", "mcp_tool_call", "web_search_call",
})


def _is_transport_error_event(ev: Dict[str, Any]) -> bool:
    """True only for Codex's OWN transport/API/turn errors — the events that carry a
    real rate-limit signal. A failed model tool call (command_execution, patch, …) is
    excluded: its payload is the generated project, not Codex's error channel."""
    item = ev.get("item")
    if isinstance(item, dict) and str(item.get("type", "")).lower() in _MODEL_ITEM_TYPES:
        return False
    t = str(ev.get("type", "")).lower()
    if "error" in t or "fail" in t:
        return True
    if ev.get("error"):
        return True
    if isinstance(item, dict) and str(item.get("status", "")).lower() in ("failed", "error"):
        return True
    return False


def _signal_matches(sig: str, haystack: str) -> bool:
    """Substring match, but bounded so a signal made only of digits (e.g. '429')
    can't match inside a longer run of word chars (an id, offset, or timestamp like
    'item_3429'). Real rate-limit text ('error 429', '429:', 'Rate limit') still hits."""
    return re.search(r"(?<!\w)" + re.escape(sig) + r"(?!\w)", haystack) is not None


def _hit_rate_limit(stdout: str, stderr: str, signals: Sequence[str]) -> Optional[str]:
    """Match rate-limit signals ONLY in Codex's own error channels: stderr, transport/
    API error events, and non-JSONL stdout noise (crash/usage text). The generated
    app's code, the agent's summary, and failed shell-command output are EXCLUDED —
    otherwise a board app that implements 'rate limiting' (or returns HTTP 429) would
    be misread as a rate-limited generation and re-queued forever."""
    if not signals:
        return None
    parts: List[str] = [stderr or ""]
    for line in (stdout or "").splitlines():
        obj = _parse_line(line)
        if obj is None:
            parts.append(line)  # unparseable stdout = likely raw error/usage text
        elif _is_transport_error_event(obj):
            parts.append(json.dumps(obj, ensure_ascii=False))
    haystack = "\n".join(parts).lower()
    for sig in signals:
        if sig and _signal_matches(sig, haystack):
            return sig
    return None


def _thread_id(events: Sequence[Dict[str, Any]]) -> Optional[str]:
    for ev in events:
        if ev.get("type") == "thread.started" and ev.get("thread_id"):
            return str(ev["thread_id"])
    return None


def _drop_session_files(env: Dict[str, str], thread_id: str) -> None:
    """Repair rounds need the session on disk (no --ephemeral) to resume it; delete
    its rollout afterwards so no transcript of the participant's run stays behind."""
    home = pathlib.Path(env.get("CODEX_HOME") or (pathlib.Path.home() / ".codex"))
    for f in (home / "sessions").glob(f"**/*{thread_id}*"):
        try:
            f.unlink()
        except OSError:
            pass


def _emit(event_sink: Optional[Callable[[Dict[str, Any]], None]], text: str) -> None:
    if event_sink is not None:
        try:
            event_sink({"type": "contract.result", "text": text})
        except Exception:
            pass


class _CheckDeadline(Exception):
    """The contract check was still running when the generation budget ran out."""


def _timed_check(check: Callable[[pathlib.Path], Any], outdir: pathlib.Path,
                 deadline: float) -> Any:
    """Run ``check(outdir)`` but stop waiting at ``deadline``. The real check also
    stops itself there (scoring.contract.check_app tears its container down); this
    bounds an injected or stuck one. Exceptions from the check are re-raised."""
    box: Dict[str, Any] = {}

    def run() -> None:
        try:
            box["result"] = check(outdir)
        except BaseException as exc:  # noqa: BLE001 - handed back to the caller
            box["error"] = exc

    th = threading.Thread(target=run, name="contract-check", daemon=True)
    th.start()
    th.join(max(0.0, deadline - time.monotonic()))
    if th.is_alive():
        raise _CheckDeadline()
    if "error" in box:
        raise box["error"]
    return box["result"]


def _harvest(
    workdir: pathlib.Path,
    outdir: pathlib.Path,
    include_globs: Sequence[str],
    exclude_globs: Sequence[str],
) -> List[str]:
    excluded: set = set()
    for pattern in exclude_globs:
        for match in workdir.glob(pattern):
            excluded.add(match.resolve())

    def is_excluded(p: pathlib.Path) -> bool:
        rp = p.resolve()
        if rp in excluded:
            return True
        for ex in excluded:
            try:
                rp.relative_to(ex)
                return True
            except ValueError:
                continue
        return False

    harvested: List[str] = []
    seen: set = set()
    for pattern in include_globs:
        for match in workdir.glob(pattern):
            if not match.is_file():
                continue
            if is_excluded(match):
                continue
            rel = match.relative_to(workdir)
            if rel in seen:
                continue
            seen.add(rel)
            dest = outdir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(match, dest)
            harvested.append(str(rel).replace(os.sep, "/"))
    return sorted(harvested)


_SEED_PARTS = ("templates", "static")
_UPLOADS = pathlib.Path("static") / "uploads"


def _seed_dir(config: Config) -> Optional[pathlib.Path]:
    """The front end we ship (``codex.seed_dir``): templates/ and static/."""
    seed = config.get("codex.seed_dir", None)
    if not seed:
        return None
    path = _resolve_under_repo(str(seed))
    if not path.is_dir():
        raise GenerationError(detail=f"codex.seed_dir not found: {path}")
    return path


def _place_seed(seed: Optional[pathlib.Path], dest: pathlib.Path) -> None:
    """Copy the seed's templates/ and static/ into the fresh workdir, plus an empty
    static/uploads/, before Codex first runs. Never re-applied: an edit Codex makes
    stays and the contract's hash check sends it back as a failure to undo."""
    if seed is None:
        return
    for part in _SEED_PARTS:
        src = seed / part
        if src.is_dir():
            shutil.copytree(src, dest / part, dirs_exist_ok=True)
    (dest / _UPLOADS).mkdir(parents=True, exist_ok=True)


def _collect(
    config: Config,
    submission_id: str,
    workdir: pathlib.Path,
    include_globs: Sequence[str],
    exclude_globs: Sequence[str],
) -> Tuple[pathlib.Path, List[str]]:
    """Fresh output dir with the harvested project as Codex left it, templates/ and
    static/ included, plus an empty static/uploads/ for the app to write to."""
    outdir = _make_output_dir(config, submission_id)
    harvested = _harvest(workdir, outdir, include_globs, exclude_globs)
    (outdir / _UPLOADS).mkdir(parents=True, exist_ok=True)
    return outdir, harvested


def _build_deps(outdir: pathlib.Path, config: Config) -> None:
    """Deps image for the harvested requirements, built now so the contract check and
    grading start it at once. Cached by requirements hash: a repair that leaves
    requirements.txt alone builds nothing. A failed build is not raised; the box then
    runs the base image and the build log reaches the boot log."""
    from scoring.shared import deps_image

    deps_image.ensure(str(outdir), config)


def _write_transcript(
    config: Config,
    submission_id: str,
    argv: Sequence[str],
    events: Sequence[Dict[str, Any]],
    stderr: str,
    returncode: Optional[int],
    elapsed: float,
    outcome: str,
    harvested: Sequence[str],
    extra_detail: Optional[str] = None,
    contract: Optional[Sequence[Dict[str, Any]]] = None,
) -> Optional[pathlib.Path]:
    # Operator-only; never contains the raw prompt. Swallows its own errors.
    tmpl = config.get("codex.transcript_dir", "data/codex_transcripts/{submission_id}")
    try:
        dir_str = str(tmpl).replace("{submission_id}", submission_id)
        tdir = _resolve_under_repo(dir_str)
        tdir.mkdir(parents=True, exist_ok=True)
        transcript = {
            "submission_id": submission_id,
            "argv": [str(a) for a in argv],
            "returncode": returncode,
            "elapsed_seconds": round(elapsed, 3),
            "outcome": outcome,
            "harvested": list(harvested),
            "detail": extra_detail,
            "contract": list(contract or []),
            "stderr": stderr,
            "events": list(events),
        }
        path = tdir / "transcript.json"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(transcript, fh, ensure_ascii=False, indent=2)
        return path
    except Exception:
        return None


def _make_output_dir(config: Config, submission_id: str) -> pathlib.Path:
    base = config.get("codex.output_base", _DEFAULT_OUTPUT_BASE)
    base_path = _resolve_under_repo(str(base))
    base_path.mkdir(parents=True, exist_ok=True)
    outdir = base_path / submission_id
    if outdir.exists():
        shutil.rmtree(outdir, ignore_errors=True)
    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


def generate(
    submission_id: str,
    prompt: str,
    *,
    config: Optional[Config] = None,
    keep_workdir: bool = False,
    event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
    model: Optional[str] = None,
    reasoning_effort: Optional[str] = None,
    contract_check: Optional[Callable[[pathlib.Path], Any]] = None,
) -> pathlib.Path:
    """Generate a Flask project for ``prompt`` and return the harvested dir.

    Codex writes only ``app.py`` (+ requirements.txt, optional .env). The front end
    (``codex.seed_dir``: templates/, static/) is ours: it is placed in the workdir
    before Codex runs and harvested back as Codex left it. The contract checks its
    hashes against the seed, so an edit fails the contract and goes back to Codex.

    ``model`` / ``reasoning_effort`` (optional) override ``codex.model`` /
    ``codex.reasoning_effort`` for this run (admin settings).
    ``event_sink`` (optional) receives each codex JSONL event live as it streams,
    powering the real-time generation view. It must never raise (errors ignored).

    Contract loop (``codex.contract_loop.enabled``): after the build, the harvested
    app is booted in the scoring sandbox and run against the hidden functional
    contract; failures go back to the SAME session via ``codex exec resume`` until
    the app passes every requirement, all within the one ``timeouts.codex_exec``
    budget (the checks count against it too). A build that never passes is a
    generation failure (``ContractFailedError``) and is never returned for grading.
    ``contract_check(outdir) -> ContractResult`` overrides the check (tests)."""
    if config is None:
        config = load_config()

    argv = _build_argv(config, model_override=model, reasoning_override=reasoning_effort)
    env = _scrubbed_env(config)
    timeout = float(config.get("timeouts.codex_exec", 600))
    deadline = time.monotonic() + timeout
    loop_cfg = config.get("codex.contract_loop", {}) or {}
    if contract_check is None and loop_cfg.get("enabled"):
        from scoring.contract import check_app

        contract_check = lambda d: check_app(str(d), config, deadline=deadline)  # noqa: E731
    signals = _rate_limit_signals(config)
    include_globs = config.get("codex.harvest.include_globs", []) or []
    exclude_globs = config.get("codex.harvest.exclude_globs", []) or []

    seed = _seed_dir(config)
    workdir = pathlib.Path(tempfile.mkdtemp(prefix=f"codexgen_{submission_id}_",
                                            dir=_workdir_base(config)))
    _place_seed(seed, workdir)

    from .activity import clear_preview_port, write_preview_port
    from .live import LiveServer

    port = _free_port()
    _self_test_env(env, port)
    # The live preview runs on its OWN port from a snapshot, so it never disturbs
    # Codex's self-tests; the web proxies it while the app is being built.
    live = LiveServer(workdir, _free_port(), env).start()
    write_preview_port(config, submission_id, live.port)

    events: List[Dict[str, Any]] = []
    stderr = ""
    returncode: Optional[int] = None
    elapsed = 0.0
    # Recorded from the live stream, so the session rollout is deleted even when the
    # first run times out before its stdout is parsed.
    session: Dict[str, str] = {}
    rounds: List[Dict[str, Any]] = []
    thread_id: Optional[str] = None

    def sink(ev: Dict[str, Any]) -> None:
        if ev.get("type") == "thread.started" and ev.get("thread_id"):
            session.setdefault("thread_id", str(ev["thread_id"]))
        if event_sink is not None:
            event_sink(ev)

    try:
        try:
            returncode, stdout, stderr, elapsed = _run_codex(
                argv, prompt + _PORT_NOTE.format(port=port), workdir, env, timeout,
                event_sink=sink,
            )
        except GenerationTimeoutError as exc:
            _write_transcript(
                config, submission_id, argv, [], "", None, 0.0,
                outcome="timeout", harvested=[], extra_detail=exc.detail,
            )
            raise

        events = _parse_jsonl(stdout)
        thread_id = _thread_id(events) or session.get("thread_id")

        # Rate limit takes priority over exit code so the queue can back off.
        matched = _hit_rate_limit(stdout, stderr, signals)
        if matched is not None:
            retry_after = compute_backoff(0, config)
            _write_transcript(
                config, submission_id, argv, events, stderr, returncode, elapsed,
                outcome="rate_limit", harvested=[],
                extra_detail=f"rate-limit signal matched: {matched!r}",
            )
            raise RateLimitError(retry_after=retry_after,
                                 detail=f"rate-limit signal matched: {matched!r}")

        outdir, harvested = _collect(config, submission_id, workdir,
                                     include_globs, exclude_globs)

        # The seed front end is always there, so "nothing written" means no app.py.
        if "app.py" not in harvested:
            shutil.rmtree(outdir, ignore_errors=True)
            _write_transcript(
                config, submission_id, argv, events, stderr, returncode, elapsed,
                outcome="no_files", harvested=harvested,
                extra_detail=f"no app.py written (rc={returncode})",
            )
            raise GenerationError(
                detail=f"codex wrote no app.py (rc={returncode})"
            )

        (outdir / "prompt.md").write_text(prompt, encoding="utf-8")
        _build_deps(outdir, config)

        if contract_check is not None:
            from scoring.contract import feedback
            from scoring.shared.sandbox import SandboxError

            min_round = float(loop_cfg.get("min_round_seconds", 60))
            check_retries = int(loop_cfg.get("check_retries", 2))

            def give_up(outcome: str, why: str, exc_type=ContractFailedError):
                shutil.rmtree(outdir, ignore_errors=True)  # never graded
                _write_transcript(
                    config, submission_id, argv, events, stderr, returncode, elapsed,
                    outcome=outcome, harvested=harvested, extra_detail=why, contract=rounds,
                )
                return exc_type(detail=why)

            rnd = 0
            check_errors = 0
            while True:
                try:
                    result = _timed_check(contract_check, outdir, deadline)
                except _CheckDeadline:
                    raise give_up("contract_failed", f"budget ran out during contract check {rnd}")
                except Exception as exc:  # noqa: BLE001 - docker trouble or a suite bug, not the app
                    check_errors += 1
                    why = f"contract check {rnd} raised {type(exc).__name__}: {exc}"
                    if check_errors > check_retries or time.monotonic() >= deadline:
                        # Not the participant's fault: a plain GenerationError, which
                        # the pipeline retries a bounded number of times.
                        raise give_up("check_error", why, GenerationError)
                    _emit(event_sink, "기능 테스트 환경 오류, 같은 빌드를 다시 검사")
                    if not isinstance(exc, SandboxError):
                        _log.warning("submission %s: %s", submission_id, why, exc_info=exc)
                    continue
                check_errors = 0
                rounds.append({"round": rnd, "booted": result.booted, "passed": result.passed,
                               "total": result.total, "failed": [r.id for r in result.failures],
                               "skipped": [r.id for r in result.requirements if getattr(r, "skipped", False)]})
                _emit(event_sink, (f"기능 테스트 {result.passed}/{result.total} 통과" if result.booted
                                   else "기능 테스트: 앱이 실행되지 않음"))
                if result.ok:
                    break
                remaining = deadline - time.monotonic()
                if not thread_id:
                    raise give_up("contract_failed", "contract failed and no session to resume")
                if remaining < min_round:
                    raise give_up("contract_failed",
                                  f"contract failed with {remaining:.0f}s left after round {rnd}")
                rnd += 1
                _emit(event_sink, f"실패한 기능 수정 요청 {rnd}회차")
                resume_argv = _build_argv(config, model_override=model,
                                          reasoning_override=reasoning_effort, resume_id=thread_id)
                try:
                    rc2, out2, err2, el2 = _run_codex(resume_argv, feedback(result), workdir, env,
                                                       remaining, event_sink=sink)
                except GenerationTimeoutError:
                    raise give_up("contract_failed", f"budget ran out during repair {rnd}")
                events += _parse_jsonl(out2)
                stderr += err2
                elapsed += el2
                returncode = rc2
                matched = _hit_rate_limit(out2, err2, signals)
                if matched is not None:
                    # Codex's limit, not the app: re-queue like a first-run rate limit.
                    shutil.rmtree(outdir, ignore_errors=True)
                    _write_transcript(
                        config, submission_id, argv, events, stderr, returncode, elapsed,
                        outcome="rate_limit", harvested=harvested, contract=rounds,
                        extra_detail=f"rate-limit signal matched in repair {rnd}: {matched!r}",
                    )
                    raise RateLimitError(retry_after=compute_backoff(0, config),
                                         detail=f"rate-limit signal matched: {matched!r}")
                # Re-check whatever the repair left, even a broken project: the next
                # round's feedback carries its boot log, and only a passing build is
                # ever returned for grading.
                outdir, harvested = _collect(config, submission_id, workdir,
                                             include_globs, exclude_globs)
                (outdir / "prompt.md").write_text(prompt, encoding="utf-8")
                _build_deps(outdir, config)

        _write_transcript(
            config, submission_id, argv, events, stderr, returncode, elapsed,
            outcome="success", harvested=harvested, contract=rounds,
        )
        return outdir

    finally:
        thread_id = thread_id or session.get("thread_id")
        if thread_id:
            _drop_session_files(env, thread_id)
        clear_preview_port(config, submission_id)
        live.stop()
        if not keep_workdir:
            shutil.rmtree(workdir, ignore_errors=True)


__all__ = ["generate", "compute_backoff"]
