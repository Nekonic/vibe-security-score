"""Operator Kali sessions: a web terminal into a Kali box that attacks one graded app.

Per session (one Kali per booth, ``kali.max_sessions``):
  * the target — the graded app booted exactly as grading boots it (``Sandbox``),
    joined to a private network under the alias ``target``;
  * the Kali box (``kali.image``) on that network, with ``~/poc/<check>.py`` for each
    dynamic check the grade failed. Each script replays the grader's own probes
    (sandbox/attack/kali_poc.py), so a demo shows what the score came from;
  * grader-side pieces a grading run also has: the SSRF callback listener, the public
    redirector, and a token-protected control API the Kali box uses to read the app's
    logs, look up callback hits and restart the target before each replay;
  * a shell (``docker exec -it ... bash``) on a pty, bridged to the browser by polling.

Lifetime: a session starts when the console page opens and is removed when the page
is left (``stop`` from the pagehide beacon) or when its terminal polling stops for
``kali.io_gap_seconds``. Every session gets fresh containers, so nothing a demo
created survives it. Opening the console again for the same submission replaces the
session; ``sid`` ties a page to its own session, so an old page never stops a newer one.

Every docker resource of a session is named ``vibe-sec-kali-<pk>-<pid>-<sid>...``:
teardown removes by that prefix, and ``sweep_orphans`` removes resources whose owning
process is gone (a web restart) — at worker start (deploy/gunicorn.conf.py) and on
every ``start``.

State lives in this process, so the web runs as ONE process (deploy/gunicorn.conf.py:
one worker, threads). Every docker path is best-effort and never raises out.
"""
from __future__ import annotations

import base64
import fcntl
import http.server
import json
import os
import pty
import re
import secrets
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from scoring.checks import by_phase
from scoring.config import load_config
from scoring.shared.sandbox import Sandbox
from scoring.shared.ssrf_callback import PublicRedirector, SSRFCallback

_BUFFER_MAX = 1_000_000
_PREFIX = "vibe-sec-kali-"
_OWNED = re.compile(r"^vibe-sec-kali-\d+-(\d+)-[0-9a-f]+")     # <pk>-<pid>-<sid>
_LEGACY = re.compile(r"^vibe-sec-kali-\d+(?:-target|-net)?$")  # fixed names before per-run ones


def _docker(*args: str, timeout: float = 60) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def _kcfg(cfg, key: str, default):
    return cfg.get(f"kali.{key}", default)


@dataclass
class Session:
    pk: int
    sid: str = field(default_factory=lambda: secrets.token_hex(4))
    token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    watch_io: bool = True                   # reap when terminal polling stops
    io_gap: float = 5.0
    box: Optional[Sandbox] = None
    ssrf: Optional[SSRFCallback] = None
    redirector: object = None
    ssrf_hosts: List[str] = field(default_factory=list)
    control: Optional[http.server.ThreadingHTTPServer] = None
    proc: Optional[subprocess.Popen] = None
    master: Optional[int] = None            # owned by the pump thread, which closes it
    fd_lock: threading.Lock = field(default_factory=threading.Lock)
    lock: threading.Lock = field(default_factory=threading.Lock)
    boot_thread: Optional[threading.Thread] = None
    logs_since: str = ""                    # target start time of the latest /reset
    out: bytearray = field(default_factory=bytearray)
    out_base: int = 0                       # absolute offset of out[0]
    cond: threading.Condition = field(default_factory=threading.Condition)
    last_io: float = field(default_factory=time.monotonic)
    ready: bool = False                     # shell is open
    closed: bool = False
    size: tuple = (120, 32)                 # latest browser terminal cols, rows

    @property
    def run(self) -> str:
        """Name prefix of every docker resource of this session."""
        return f"{_PREFIX}{self.pk}-{os.getpid()}-{self.sid}"

    @property
    def kali(self) -> str:
        return self.run

    @property
    def network(self) -> str:
        return f"{self.run}-net"

    def emit(self, data: bytes) -> None:
        with self.cond:
            self.out += data
            if len(self.out) > _BUFFER_MAX:
                drop = len(self.out) - _BUFFER_MAX
                del self.out[:drop]
                self.out_base += drop
            self.cond.notify_all()

    def say(self, text: str) -> None:
        self.emit((text + "\r\n").encode())

    def take(self, attr: str):
        """Detach a part so exactly one teardown closes it."""
        with self.lock:
            part = getattr(self, attr)
            setattr(self, attr, None)
        return part


_SESSIONS: Dict[int, Session] = {}
_LOCK = threading.Lock()
_REAPER_STARTED = False


# --- control API (Kali box -> grader) ------------------------------------------
def _control_server(sess: Session) -> http.server.ThreadingHTTPServer:
    class Handler(http.server.BaseHTTPRequestHandler):
        def _reply(self, code: int, body: str) -> None:
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _authed(self) -> bool:
            if secrets.compare_digest(self.headers.get("X-Token", ""), sess.token):
                return True
            self._reply(403, "forbidden")
            return False

        def do_GET(self):
            if not self._authed():
                return
            url = urllib.parse.urlsplit(self.path)
            if url.path == "/logs":
                # Only the current boot's log: a restart keeps the container's log file.
                since = ["--since", sess.logs_since] if sess.logs_since else []
                p = _docker("logs", "--tail", "2000", *since, sess.box.container_name, timeout=15)
                return self._reply(200, (p.stdout or "") + (p.stderr or ""))
            if url.path == "/hit":
                token = urllib.parse.parse_qs(url.query).get("token", [""])[0]
                return self._reply(200, "1" if sess.ssrf and sess.ssrf.was_hit(token) else "0")
            self._reply(404, "")

        def do_POST(self):
            if not self._authed():
                return
            if urllib.parse.urlsplit(self.path).path == "/reset":
                # A fresh app per replay, as each grading run boots a fresh container:
                # the restart re-creates the tmpfs DB and re-runs the entrypoint, which
                # only copies the app and starts it (deps are in the image). No stop grace:
                # the app is PID 1 and ignores SIGTERM, and its state is thrown away anyway.
                name = sess.box.container_name
                _docker("restart", "-t", "0", name)
                started = _docker("inspect", "-f", "{{.State.StartedAt}}", name, timeout=15)
                sess.logs_since = started.stdout.strip() if started.returncode == 0 else ""
                return self._reply(200 if sess.box._wait_for_boot() else 503, "")
            self._reply(404, "")

        def log_message(self, *_a):
            pass

    srv = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --- setup -------------------------------------------------------------------
def _dynamic_ids() -> List[str]:
    return [c.id for c in by_phase("dynamic") if c.id != "functional"]


def _poc_files(sub, sess: Session) -> Dict[str, str]:
    dyn = set(_dynamic_ids())
    findings = [f for f in (sub.findings or []) if f.get("check_id") in dyn]
    expected = {f["check_id"]: [f.get("score", 0), bool(f.get("passed")), bool(f.get("skipped"))]
                for f in findings}
    info = {
        "control": f"http://host.docker.internal:{sess.control.server_address[1]}",
        "token": sess.token,
        "ssrf_port": sess.ssrf.port if sess.ssrf else None,
        "ssrf_hosts": sess.ssrf_hosts,
        "redirector": getattr(sess.redirector, "ip", None),
        "expected": expected,
    }
    files = {".session.json": json.dumps(info, ensure_ascii=False)}
    for f in findings:
        if f.get("passed") or f.get("skipped"):
            continue
        cid = f["check_id"]
        files[f"{cid}.py"] = (f'"""{f.get("label", cid)}: 채점 때와 같은 검사를 대상 앱에 다시 실행한다."""\n'
                              f"import sys\n\nimport kali_poc\n\nsys.exit(kali_poc.run({cid!r}))\n")
    return files


def _copy_into(container: str, files: Dict[str, str], dest: str) -> None:
    tmp = tempfile.mkdtemp(prefix="vibe-kali-")
    try:
        for name, text in files.items():
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as fh:
                fh.write(text)
        _docker("cp", f"{tmp}/.", f"{container}:{dest}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _open_shell(sess: Session) -> None:
    master, slave = pty.openpty()
    cols, rows = sess.size
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    sess.proc = subprocess.Popen(
        ["docker", "exec", "-it", "-e", "TERM=xterm-256color", sess.kali, "bash", "-l"],
        stdin=slave, stdout=slave, stderr=slave, start_new_session=True, close_fds=True)
    os.close(slave)
    sess.master = master

    def pump():
        # This thread owns ``master``: teardown only kills the shell, the read then
        # fails and the fd is closed here, so no other thread can use the number
        # after the OS hands it out again.
        try:
            while True:
                try:
                    data = os.read(master, 65536)
                except OSError:
                    break
                if not data:
                    break
                sess.emit(data)
        finally:
            with sess.fd_lock:
                sess.master = None
                os.close(master)
            sess.closed = True
            sess.say("\r\n세션 종료")

    threading.Thread(target=pump, daemon=True).start()


def _redirector(cfg, box: Sandbox, sess: Session):
    """The grading run's public redirector (scoring.engine.runner._start_redirector),
    named under the session prefix so teardown and the orphan sweep find it."""
    rcfg = cfg.get("sandbox.ssrf_redirector", {}) or {}
    if not rcfg.get("enabled", True):
        return None
    red = PublicRedirector(
        image=str(cfg.get("sandbox.image", "vibe-sec-sandbox:latest")),
        network=str(rcfg.get("network", "vibe-sec-ssrfpub")),
        subnet=str(rcfg.get("subnet", "11.137.0.0/24")),
        container=f"{sess.run}-redir",
    )
    sess.redirector = red
    red.__enter__()
    if not red.attach(box.container_name):
        sess.take("redirector")
        red.__exit__(None, None, None)
    return sess.redirector


def _boot(sub, sess: Session, cfg) -> None:
    """Build the session step by step. A ``stop`` during boot only marks the session
    closed and removes what exists; each step checks ``closed`` so nothing new is
    made after it, and the final teardown here removes whatever a step in flight made."""
    try:
        sess.say("대상 앱 부팅 중...")
        box = Sandbox(sub.workdir, cfg)
        box.container_name = f"{sess.run}-target"
        sess.box = box
        box.__enter__()
        if sess.closed:
            return
        if box.boot_failed:
            sess.say("대상 앱 부팅 실패")
            sess.say((box.infra_error or box.logs(tail=20)).replace("\n", "\r\n"))
            return
        # Read the bridge gateway before joining more networks (inspect would list
        # one gateway per network) — the same host addresses a grading run uses.
        sess.ssrf_hosts = [h for h in ("host.docker.internal", box.host_gateway()) if h]
        _docker("network", "create", sess.network)
        _docker("network", "connect", "--alias", "target", sess.network, box.container_name)
        if sess.closed:
            return
        sess.ssrf = SSRFCallback().__enter__()
        _redirector(cfg, box, sess)
        sess.control = _control_server(sess)
        if sess.closed:
            return

        sess.say("Kali 준비 중...")
        run = _docker(
            "run", "-d", "--name", sess.kali, "--hostname", "kali", "--network", sess.network,
            "--add-host", "host.docker.internal:host-gateway",
            "--memory", str(_kcfg(cfg, "memory", "2g")), "--cpus", str(_kcfg(cfg, "cpus", "2")),
            "--pids-limit", str(_kcfg(cfg, "pids_limit", 512)),
            str(_kcfg(cfg, "image", "vibe-sec-attack:latest")))
        if run.returncode != 0:
            sess.say("Kali 실행 실패: " + (run.stderr or run.stdout).strip())
            return
        if sess.closed:
            return
        _copy_into(sess.kali, _poc_files(sub, sess), "/root/poc")
        _copy_into(sess.kali, {"motd": f"공격 대상: http://target:5000  ·  제출 #{sub.pk}\n"}, "/etc")
        if sess.closed:
            return
        _open_shell(sess)
        sess.ready = True
    except Exception as exc:  # never crash the web process
        sess.say(f"세션 시작 실패: {exc}")
    finally:
        # A failed boot stays in _SESSIONS only as closed output for the page to show;
        # its resources go now, and start() replaces it instead of reusing it.
        if sess.closed or not sess.ready:
            _teardown(sess)


def _remove_run(run: str) -> None:
    """Remove every container and network named under ``run``."""
    try:
        ids = _docker("ps", "-aq", "--filter", f"name={run}").stdout.split()
        if ids:
            _docker("rm", "-f", *ids)
        nets = _docker("network", "ls", "-q", "--filter", f"name={run}").stdout.split()
        if nets:
            _docker("network", "rm", *nets)
    except Exception:
        pass


def _teardown(sess: Session) -> None:
    """Idempotent and safe to run while ``_boot`` is still going. Docker resources go
    first, in one removal (the redirector container included), then the in-process
    listeners."""
    sess.closed = True
    proc = sess.take("proc")
    if proc is not None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)   # the pump then closes the pty itself
        except Exception:
            pass
    _remove_run(sess.run)
    if proc is not None:
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    sess.take("redirector")                     # its container went with the run
    ssrf = sess.take("ssrf")
    try:
        if ssrf is not None:
            ssrf.__exit__(None, None, None)
    except Exception:
        pass
    control = sess.take("control")
    if control is not None:
        control.shutdown()
        control.server_close()


def _close(sess: Session) -> None:
    """Teardown for a session already out of _SESSIONS. While its boot is still in a
    step (a docker run, the target's boot wait), keep removing what that step makes,
    so nothing outlives the stop by more than a moment."""
    _teardown(sess)
    t = sess.boot_thread
    while t is not None and t.is_alive():
        t.join(timeout=0.5)
        _remove_run(sess.run)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def sweep_orphans() -> None:
    """Remove Kali-session containers and networks no live session owns: those of a
    process that is gone (a web restart), this process's untracked ones, and the
    fixed-name ones of older versions."""
    try:
        names = _docker("ps", "-a", "--filter", f"name={_PREFIX}", "--format", "{{.Names}}").stdout.split()
        nets = _docker("network", "ls", "--filter", f"name={_PREFIX}", "--format", "{{.Name}}").stdout.split()
    except Exception:
        return
    with _LOCK:  # after listing: a resource listed was made by a session already here
        live = [s.run for s in _SESSIONS.values()]
    me = os.getpid()

    def orphan(name: str) -> bool:
        if not name.startswith(_PREFIX) or any(name.startswith(r) for r in live):
            return False
        m = _OWNED.match(name)
        if m:
            pid = int(m.group(1))
            return pid == me or not _alive(pid)
        return bool(_LEGACY.match(name))

    dead = [n for n in names if orphan(n)]
    try:
        if dead:
            _docker("rm", "-f", *dead)
        dead_nets = [n for n in nets if orphan(n)]
        if dead_nets:
            _docker("network", "rm", *dead_nets)
    except Exception:
        pass


def reap_once(now: Optional[float] = None) -> List[Session]:
    """Remove sessions whose page stopped polling (window closed, tab killed, network
    gone), and failed or ended ones once their page has read the last output."""
    now = time.monotonic() if now is None else now
    with _LOCK:
        stale = [pk for pk, s in _SESSIONS.items()
                 if (s.watch_io or s.closed) and now - s.last_io > s.io_gap]
        gone = [_SESSIONS.pop(pk) for pk in stale]
    for sess in gone:
        threading.Thread(target=_close, args=(sess,), daemon=True).start()
    return gone


def _reap() -> None:
    while True:
        time.sleep(1)
        try:
            reap_once()
        except Exception:
            pass


def _ensure_reaper() -> None:
    global _REAPER_STARTED
    with _LOCK:
        if _REAPER_STARTED:
            return
        _REAPER_STARTED = True
    threading.Thread(target=_reap, daemon=True, name="kali-reaper").start()


def startup() -> None:
    """Web process start: clear what a previous process left, start the reaper."""
    _ensure_reaper()
    threading.Thread(target=sweep_orphans, daemon=True).start()


# --- public API ----------------------------------------------------------------
def start(sub, watch_io: bool = True) -> dict:
    """Start a fresh session for ``sub``, replacing any earlier one for it. Returns at
    once with the session id; boot progress and then the shell stream through ``io``.
    ``watch_io=False`` (verify_kali) keeps it until ``stop`` instead of reaping it
    when no page polls."""
    startup()
    cfg = load_config()
    limit = int(_kcfg(cfg, "max_sessions", 1))
    with _LOCK:
        busy = [s for pk, s in _SESSIONS.items() if pk != sub.pk and not s.closed]
        if len(busy) >= limit:
            return {"ok": False, "error": f"Kali 세션 사용 중 · 최대 {limit}개"}
        old = _SESSIONS.pop(sub.pk, None)
        sess = _SESSIONS[sub.pk] = Session(
            pk=sub.pk, watch_io=watch_io, io_gap=float(_kcfg(cfg, "io_gap_seconds", 5)))
    if old is not None:
        threading.Thread(target=_close, args=(old,), daemon=True).start()
    sess.boot_thread = threading.Thread(target=_boot, args=(sub, sess, cfg), daemon=True)
    sess.boot_thread.start()
    return {"ok": True, "sid": sess.sid}


def session(pk: int, sid: str) -> Optional[Session]:
    with _LOCK:
        sess = _SESSIONS.get(pk)
    return sess if sess is not None and sess.sid == sid else None


def io(pk: int, sid: str, data: str = "", since: int = 0, cols: int = 0, rows: int = 0,
       wait: float = 0.5) -> dict:
    """Send keystrokes, apply a resize, and return terminal output after ``since``.
    Each call also keeps the session alive (see ``_reap``)."""
    sess = session(pk, sid)
    if sess is None:
        return {"ok": False, "alive": False}
    sess.last_io = time.monotonic()
    if cols and rows:
        sess.size = (cols, rows)            # applied when the shell opens, if not yet
    with sess.fd_lock:
        if sess.master is not None:
            try:
                if cols and rows:
                    fcntl.ioctl(sess.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
                    sess.proc.send_signal(signal.SIGWINCH)
                if data:
                    os.write(sess.master, data.encode())
            except (OSError, AttributeError):
                pass
    with sess.cond:
        end = sess.out_base + len(sess.out)
        if since >= end and not data:
            sess.cond.wait(timeout=wait)
            end = sess.out_base + len(sess.out)
        start_at = max(since, sess.out_base)
        chunk = bytes(sess.out[start_at - sess.out_base:])
    return {"ok": True, "alive": not sess.closed, "from": start_at, "next": end,
            "out": base64.b64encode(chunk).decode()}


def stop(pk: int, sid: Optional[str] = None, wait: bool = False) -> dict:
    """Remove the session (only the one ``sid`` names, when given). ``wait`` returns
    once boot has ended and every container and network is gone."""
    with _LOCK:
        sess = _SESSIONS.get(pk)
        if sess is None or (sid is not None and sess.sid != sid):
            return {"ok": True}
        _SESSIONS.pop(pk)
    if not wait:
        threading.Thread(target=_close, args=(sess,), daemon=True).start()
        return {"ok": True}
    _close(sess)
    _teardown(sess)
    return {"ok": True}
