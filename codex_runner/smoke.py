"""Real Codex generation smoke test (dev/operator). Needs an installed CLI +
`codex login`. Exit codes: 0 ok · 2 not found · 3 rate-limited · 4 timeout · 5 failed."""
from __future__ import annotations

import subprocess
import sys

from scoring.config import load_config

from . import generate
from .errors import GenerationError, GenerationTimeoutError, RateLimitError
from .runner import _binary_argv

DEFAULT_PROMPT = (
    "Flask로 회원가입(/signup), 로그인(/login), 글 목록/작성(GET·POST /posts)이 "
    "되는 간단한 게시판을 만들어줘. HTML은 templates/ 폴더의 Jinja 템플릿으로, "
    "결과물은 templates/, app.py, requirements.txt 형태로."
)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    prompt = argv[0] if argv else DEFAULT_PROMPT

    config = load_config()
    prefix = _binary_argv(config)
    print(f"[smoke] resolved codex argv prefix: {prefix}")

    try:
        r = subprocess.run(
            [*prefix, "--version"], capture_output=True, text=True, timeout=30
        )
        ver = (r.stdout or r.stderr or "").strip().splitlines()[:1]
        print(f"[smoke] codex --version rc={r.returncode}: {ver[0] if ver else ''}")
    except FileNotFoundError:
        print("[smoke] ERROR: codex not found on PATH. Install it and run "
              "`codex login` first.")
        return 2
    except Exception as exc:
        print(f"[smoke] version check failed (continuing): {exc}")

    print("[smoke] generating with REAL codex (needs an active `codex login`)...")
    try:
        outdir = generate("smoke", prompt, config=config)
    except RateLimitError as exc:
        print(f"[smoke] RATE LIMITED (retry_after={exc.retry_after}s): {exc}")
        return 3
    except GenerationTimeoutError as exc:
        print(f"[smoke] TIMEOUT: {exc}")
        return 4
    except GenerationError as exc:
        print(f"[smoke] GENERATION FAILED: {exc}")
        print("        hint: not logged in? run `codex login`. wrong model/flags? "
              "check config/scoring.yaml `codex.*`.")
        return 5

    print(f"[smoke] OK -> {outdir}")
    for p in sorted(outdir.rglob("*")):
        if p.is_file():
            print(f"        {p.relative_to(outdir)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
