"""Codex runner: drive ``codex exec`` to generate a Flask project."""
from __future__ import annotations

import json
import os
import pathlib
import queue
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
    GenerationError,
    GenerationTimeoutError,
    RateLimitError,
)

_IS_WINDOWS = os.name == "nt"
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


def _build_argv(config: Config) -> List[str]:
    sandbox = config.get("codex.exec_flags.sandbox", "workspace-write")
    extra = config.get("codex.exec_flags.extra", []) or []
    model = config.get("codex.model", "") or ""
    argv = [
        *_binary_argv(config),
        "exec",
        "--sandbox",
        str(sandbox),
        *[str(f) for f in extra],
    ]
    # Omit --model when empty: ChatGPT-account auth rejects API-only ids like gpt-5-codex.
    if model:
        argv += ["--model", str(model)]
    argv += ["-"]  # prompt via stdin
    return argv


def _redacted_argv(argv: Sequence[str]) -> List[str]:
    return [str(a) for a in argv]


def _scrubbed_env(config: Config) -> Dict[str, str]:
    # Blank the API-key vars so an API key can never trigger paid billing (ChatGPT login only).
    env = dict(os.environ)
    for key in config.get("codex.blank_env", []) or []:
        env.pop(str(key), None)
    codex_home = config.get("codex.codex_home", None)
    if codex_home:
        env["CODEX_HOME"] = str(codex_home)
    return env


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
    events: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events


def _hit_rate_limit(stdout: str, stderr: str, signals: Sequence[str]) -> Optional[str]:
    if not signals:
        return None
    haystack = (stdout + "\n" + stderr).lower()
    for sig in signals:
        if sig and sig in haystack:
            return sig
    return None


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
) -> Optional[pathlib.Path]:
    # Operator-only; never contains the raw prompt. Swallows its own errors.
    tmpl = config.get("codex.transcript_dir", "data/codex_transcripts/{submission_id}")
    try:
        dir_str = str(tmpl).replace("{submission_id}", submission_id)
        tdir = _resolve_under_repo(dir_str)
        tdir.mkdir(parents=True, exist_ok=True)
        transcript = {
            "submission_id": submission_id,
            "argv_redacted": _redacted_argv(argv),
            "returncode": returncode,
            "elapsed_seconds": round(elapsed, 3),
            "outcome": outcome,
            "harvested": list(harvested),
            "detail": extra_detail,
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
) -> pathlib.Path:
    """Generate a Flask project for ``prompt`` and return the harvested dir.

    ``event_sink`` (optional) receives each codex JSONL event live as it streams,
    powering the real-time generation view. It must never raise (errors ignored)."""
    if config is None:
        config = load_config()

    argv = _build_argv(config)
    env = _scrubbed_env(config)
    timeout = float(config.get("timeouts.codex_exec", 600))
    signals = _rate_limit_signals(config)
    include_globs = config.get("codex.harvest.include_globs", []) or []
    exclude_globs = config.get("codex.harvest.exclude_globs", []) or []

    workdir = pathlib.Path(tempfile.mkdtemp(prefix=f"codexgen_{submission_id}_"))

    events: List[Dict[str, Any]] = []
    stderr = ""
    returncode: Optional[int] = None
    elapsed = 0.0
    try:
        try:
            returncode, stdout, stderr, elapsed = _run_codex(
                argv, prompt, workdir, env, timeout, event_sink=event_sink
            )
        except GenerationTimeoutError as exc:
            _write_transcript(
                config, submission_id, argv, [], "", None, 0.0,
                outcome="timeout", harvested=[], extra_detail=exc.detail,
            )
            raise

        events = _parse_jsonl(stdout)

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

        outdir = _make_output_dir(config, submission_id)
        harvested = _harvest(workdir, outdir, include_globs, exclude_globs)

        if not harvested:
            shutil.rmtree(outdir, ignore_errors=True)
            _write_transcript(
                config, submission_id, argv, events, stderr, returncode, elapsed,
                outcome="no_files", harvested=[],
                extra_detail=f"no harvestable files (rc={returncode})",
            )
            raise GenerationError(
                detail=f"codex produced no harvestable files (rc={returncode})"
            )

        (outdir / "prompt.md").write_text(prompt, encoding="utf-8")

        _write_transcript(
            config, submission_id, argv, events, stderr, returncode, elapsed,
            outcome="success", harvested=harvested,
        )
        return outdir

    finally:
        if not keep_workdir:
            shutil.rmtree(workdir, ignore_errors=True)


__all__ = ["generate", "compute_backoff"]
