"""Practice range: one generated app (`target`) and a Kali box on a private docker
network, plus an optional AI pentest agent (Codex CLI inside Kali).

    python sandbox/kali/range.py up data/generated/42 --name r42      # start
    docker exec -it vibe-range-r42-kali bash                           # attack by hand
    python sandbox/kali/range.py agent r42 --minutes 10 --out r42.json # AI pentest
    python sandbox/kali/range.py down r42                              # clean up

The target runs exactly like the scoring sandbox (same image, read-only app mount,
tmpfs workdir, resource limits). Inside the range it is reachable as
http://target:5000. The network is a user-defined bridge, not --internal: the
agent's Codex CLI calls the API.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

_REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

from scoring.config import load_config  # noqa: E402
from scoring.shared import deps_image  # noqa: E402

KALI_IMAGE = "vibe-sec-kali:latest"


def _docker(*args: str, check: bool = True, timeout: float = 120, **kw) -> subprocess.CompletedProcess:
    proc = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout, **kw)
    if check and proc.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:2])} failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return proc


def _names(name: str):
    return f"vibe-range-{name}", f"vibe-range-{name}-target", f"vibe-range-{name}-kali"


def up(app_dir: str, name: str, boot_timeout: float = 90) -> None:
    cfg = load_config()
    net, target, kali = _names(name)
    src = str(pathlib.Path(app_dir).resolve())
    if not (pathlib.Path(src) / "app.py").is_file():
        raise SystemExit(f"{src}/app.py 가 없음")
    uid = int(cfg.get("sandbox.run_as_uid", 10001))
    _docker("network", "create", net)
    _docker("run", "-d", "--name", target, "--network", net, "--network-alias", "target",
            "-e", "APP_DIR=/app", "-e", "DATABASE=/work/app.db",
            "-v", f"{src}:/app:ro",
            "--tmpfs", f"/work:rw,size=128m,uid={uid}", "--tmpfs", f"/tmp:rw,size=64m,uid={uid}",
            "--memory", str(cfg.get("sandbox.memory", "512m")), "--cpus", str(cfg.get("sandbox.cpus", "1.0")),
            "--pids-limit", str(cfg.get("sandbox.pids_limit", 256)),
            deps_image.ensure(src, cfg)[0])
    _docker("run", "-d", "--name", kali, "--hostname", "kali", "--network", net, KALI_IMAGE)
    deadline = time.monotonic() + boot_timeout
    while time.monotonic() < deadline:
        r = _docker("exec", kali, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                    "http://target:5000/posts", check=False, timeout=15)
        if r.stdout.strip() not in ("", "000"):
            print(f"레인지 {name} 준비됨: docker exec -it {kali} bash  (대상 http://target:5000)")
            return
        time.sleep(2)
    print(_docker("logs", "--tail", "30", target, check=False).stdout)
    raise SystemExit("대상 앱이 부팅되지 않음 (위 로그 참고)")


def down(name: str) -> None:
    net, target, kali = _names(name)
    _docker("rm", "-f", target, kali, check=False)
    _docker("network", "rm", net, check=False)


def _spec_features() -> str:
    """The public feature list of config/default_prompt.md (what participants see)."""
    text = (_REPO / "config" / "default_prompt.md").read_text(encoding="utf-8")
    start = text.find("## 모델")
    end = text.find("## 검증")
    return text[start:end].strip() if start != -1 and end != -1 else text


def agent(name: str, minutes: float, model: str, effort: str, out: str) -> dict:
    """Run Codex as a black-box pentester inside the range's Kali box; return its
    findings (also written to ``out``). The ChatGPT login is copied in for the run
    and removed afterwards."""
    _, _, kali = _names(name)
    auth = pathlib.Path(os.environ.get("CODEX_HOME", pathlib.Path.home() / ".codex")) / "auth.json"
    prompt = (pathlib.Path(__file__).with_name("agent_prompt.md").read_text(encoding="utf-8")
              .replace("{budget_minutes}", str(int(minutes))).replace("{spec}", _spec_features()))
    _docker("exec", kali, "mkdir", "-p", "/root/.codex", "/root/work")
    _docker("cp", str(auth), f"{kali}:/root/.codex/auth.json")
    argv = ["docker", "exec", "-i", "-w", "/root/work", kali, "codex", "exec",
            "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check", "--ephemeral",
            "--json", "--model", model, "-c", f"model_reasoning_effort={effort}",
            "--output-schema", "/opt/range/findings.schema.json", "-o", "/root/work/findings.json", "-"]
    t0 = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(argv, input=prompt, capture_output=True, text=True, timeout=minutes * 60 + 120)
        stdout = proc.stdout
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        _docker("exec", kali, "pkill", "-f", "codex", check=False)
    finally:
        _docker("exec", kali, "rm", "-f", "/root/.codex/auth.json", check=False)
    elapsed = round(time.monotonic() - t0, 1)
    raw = _docker("exec", kali, "cat", "/root/work/findings.json", check=False).stdout
    try:
        report = json.loads(raw)
    except ValueError:
        report = {"summary": "결과 JSON 없음", "findings": []}
    commands = sum(1 for line in stdout.splitlines() if '"command_execution"' in line and '"item.completed"' in line)
    report.update({"range": name, "model": model, "effort": effort, "elapsed_seconds": elapsed,
                   "timed_out": timed_out, "commands": commands})
    pathlib.Path(out).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    pathlib.Path(out).with_suffix(".events.jsonl").write_text(stdout, encoding="utf-8")
    return report


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    u = sub.add_parser("up"); u.add_argument("app_dir"); u.add_argument("--name", required=True)
    d = sub.add_parser("down"); d.add_argument("name")
    a = sub.add_parser("agent"); a.add_argument("name")
    a.add_argument("--minutes", type=float, default=10); a.add_argument("--model", default="gpt-6.1-sol")
    a.add_argument("--effort", default="medium"); a.add_argument("--out", required=True)
    args = p.parse_args()
    if args.cmd == "up":
        up(args.app_dir, args.name)
    elif args.cmd == "down":
        down(args.name)
    else:
        r = agent(args.name, args.minutes, args.model, args.effort, args.out)
        print(json.dumps({k: r[k] for k in ("elapsed_seconds", "timed_out", "commands")}, ensure_ascii=False),
              f"findings={len(r.get('findings', []))}")


if __name__ == "__main__":
    main()
