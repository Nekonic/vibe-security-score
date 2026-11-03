"""Functional contract for the generated board app: boot it in the scoring sandbox,
run the hidden requirement suite, and phrase failures as repair feedback for the
generation loop. Behavior only — never a security check (see suite.py)."""
from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import threading
import time
import uuid
from typing import Optional

from ..config import Config, load_config
from ..shared.sandbox import Sandbox
from ..shared.ssrf_callback import start_redirector
from .suite import EGRESS_URL, ContractResult, Requirement, run_contract

_LOG_TAIL = 4000
_ENTRY_FILES = ("app.py", "wsgi.py", "main.py")
# Fetches the preview URL from INSIDE the app's container and prints its <title>: R18
# can only demand a link preview when the app itself could have fetched the page.
_EGRESS_PROBE = (
    "import re,urllib.request as u\n"
    "b=u.urlopen(%r,timeout=8).read(65536).decode('utf-8','replace')\n"
    "m=re.search(r'<title[^>]*>([^<]*)',b,re.I)\n"
    "print(m.group(1).strip() if m else '')\n"
)


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SEED_PARTS = ("templates", "static")
_UPLOADS = os.path.join("static", "uploads")


def _tree_hashes(root: pathlib.Path) -> dict:
    """sha256 of every file under root/templates and root/static, uploads excluded."""
    out = {}
    for part in _SEED_PARTS:
        base = root / part
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            rel = f.relative_to(root).as_posix()
            if f.is_file() and not rel.startswith(_UPLOADS.replace(os.sep, "/") + "/"):
                out[rel] = hashlib.sha256(f.read_bytes()).hexdigest()
    return out


def seed_unchanged(app_dir: str, config: Config) -> Optional[Requirement]:
    """The shipped templates/ and static/ must come back byte for byte. None when no
    seed is configured."""
    seed = config.get("codex.seed_dir", None)
    if not seed:
        return None
    seed_path = pathlib.Path(seed)
    if not seed_path.is_absolute():
        seed_path = _REPO_ROOT / seed_path
    want, got = _tree_hashes(seed_path), _tree_hashes(pathlib.Path(app_dir))
    changed = sorted(k for k in want if got.get(k) != want[k])
    added = sorted(k for k in got if k not in want)
    actual = "변경 없음" if not (changed or added) else ", ".join(
        [f"{k} 바뀜" if k in got else f"{k} 없음" for k in changed] + [f"{k} 추가됨" for k in added])
    return Requirement(id="R00", title="제공된 templates와 static은 원본 그대로", passed=not (changed or added),
                       request="templates/, static/",
                       expected="제공된 파일과 내용이 같고 새 파일이 없다. 바꾼 파일은 원래대로 되돌린다",
                       actual=actual)


def _egress_title(box: Sandbox, url: str = EGRESS_URL) -> Optional[str]:
    """``<title>`` of ``url`` as seen from the app's container, or None when the
    container can't reach it (then R18 is undecidable, not failed)."""
    for py in ("python", "python3"):
        try:
            proc = subprocess.run(
                ["docker", "exec", box.container_name, py, "-c", _EGRESS_PROBE % url],
                capture_output=True, text=True, timeout=15,
            )
        except Exception:
            return None
        if proc.returncode == 0:
            return proc.stdout.strip() or None
        if "executable file not found" not in (proc.stderr or ""):
            return None
    return None


_REDIRECTOR_WAIT = 10.0  # its start takes ~2 s, measured


def _remove_redirector(starter: threading.Thread, started: dict) -> None:
    """Remove R18's page once its start has finished, however long that takes."""
    starter.join()
    if started.get("red") is not None:
        started["red"].__exit__(None, None, None)


def check_app(app_dir: str, config: Optional[Config] = None,
              deadline: Optional[float] = None) -> ContractResult:
    """Boot ``app_dir`` exactly as scoring does and run the contract against it.
    ``deadline`` (``time.monotonic()``) bounds the whole check: past it the client
    stops sending and the container is torn down, which also cuts off a response
    that never ends."""
    config = config or load_config()
    seed_req = seed_unchanged(app_dir, config)
    if not any(os.path.isfile(os.path.join(app_dir, f)) for f in _ENTRY_FILES):
        return ContractResult(booted=False, boot_log="프로젝트 폴더에 app.py가 없다.")
    # R18's page: the grader's public-looking control page, its title carrying a
    # fresh nonce, so only an app that really fetched the URL can show it (#51
    # answered a fixed example.com title without fetching). example.com only when
    # docker can't set the page up. Started while the app boots and removed in the
    # background: ~2 s up and ~1 s down, measured, off every contract round. The
    # remover is not a daemon thread, so a short-lived process waits for it at exit.
    # Its URL is a host name unique to this check, so concurrent checks sharing the
    # network never answer for each other and IP-address URLs are not required. The
    # name is a nip.io name carrying the page's address: public DNS answers it with
    # that same address, so a preview that resolves names itself still reaches it.
    nonce = uuid.uuid4().hex[:12]
    started: dict = {}
    starter = threading.Thread(
        target=lambda: started.update(red=start_redirector(
            config, None, nonce=nonce, alias=f"p{nonce}.{{ip}}.nip.io")),
        daemon=True)
    starter.start()
    try:
        with Sandbox(app_dir, config) as box:
            # Bounded: docker can stall (several calls, 30 s each); then R18 uses
            # example.com.
            wait = _REDIRECTOR_WAIT if deadline is None else min(
                _REDIRECTOR_WAIT, max(0.0, deadline - time.monotonic()))
            starter.join(wait)
            box.raise_if_infra_error()
            if box.boot_failed:
                return ContractResult(booted=False, boot_log=box.logs(60)[-3000:])
            red = None if starter.is_alive() else started.get("red")
            if red is not None and not red.attach(box.container_name):
                red = None
            timer = None
            if deadline is not None:
                timer = threading.Timer(max(0.0, deadline - time.monotonic()), box._teardown)
                timer.daemon = True
                timer.start()
            url = red.page_url() if red is not None else EGRESS_URL
            title = _egress_title(box, url)
            if title is None and url != EGRESS_URL:
                # The page is up but the app's container cannot reach it by name.
                url = EGRESS_URL
                title = _egress_title(box, url)
            try:
                reqs = run_contract(box.base_url, logs=lambda: box.logs(_LOG_TAIL),
                                    deadline=deadline, egress_title=title, egress_url=url)
            finally:
                if timer is not None:
                    timer.cancel()
    finally:
        threading.Thread(target=_remove_redirector, args=(starter, started)).start()
    if seed_req is not None:
        reqs = [seed_req, *reqs]
    return ContractResult(booted=True, requirements=reqs)


def feedback(result: ContractResult, limit: int = 12) -> str:
    """Repair prompt for ``codex exec resume``: what failed, the request, what was
    expected and what came back. Never the test source."""
    if not result.booted:
        return (
            "채점 환경에서 `python app.py`로 앱을 실행했더니 서버가 뜨기 전에 종료됐다. "
            "아래 로그의 원인을 고치고, 서버가 실제로 떠서 요청에 응답하는지 직접 확인하라.\n\n"
            f"```\n{result.boot_log.strip()[-2500:]}\n```\n"
        )
    lines = [
        f"채점 환경에서 요구사항 기능 테스트를 돌렸더니 {result.total}개 중 "
        f"{result.total - result.passed}개가 실패했다. 아래 항목을 명세대로 고쳐라. "
        "이미 통과한 기능은 깨뜨리지 말고, 고친 뒤 실제 HTTP 요청으로 다시 확인하라.",
        "",
    ]
    for r in result.failures[:limit]:
        lines += [
            f"- [{r.id}] {r.title}",
            f"  요청: {r.request}",
            f"  기대: {r.expected}",
            f"  실제: {r.actual}",
        ]
    extra = len(result.failures) - limit
    if extra > 0:
        lines.append(f"- 그 밖에 {extra}개 더 실패")
    return "\n".join(lines) + "\n"


__all__ = ["ContractResult", "Requirement", "check_app", "feedback", "run_contract"]
