"""External SQLi tool wrapper: sqlmap. ``run_sqlmap(base_url, cfg) -> SqlmapOutcome``.

``ran=False`` means sqlmap produced no verdict (disabled/missing/timeout/error); the
``reason`` states which. It describes the condition only — it does NOT prescribe a
fallback: outside ``--dev`` the caller (``dynamic_sqli``) hard-fails on ``ran=False``
rather than degrading to the built-in oracle.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class SqlmapOutcome:
    ran: bool = False
    injectable: bool = False  # only meaningful when ran is True
    reason: str = ""
    evidence: List[str] = field(default_factory=list)


_STRONG_SIGNS = (
    "sqlmap identified the following injection point",
    "the back-end dbms is",
    "is vulnerable",
    "appears to be injectable",
)


def _is_available(binary: str) -> bool:
    if not binary:
        return False
    if os.path.sep in binary or (os.altsep and os.altsep in binary):
        return os.path.isfile(binary)
    return shutil.which(binary) is not None


def parse_sqlmap_output(text: str) -> bool:
    """True if sqlmap output indicates an injectable parameter."""
    low = (text or "").lower()
    if any(sign in low for sign in _STRONG_SIGNS):
        return True
    if "type: " in low and ("blind" in low or "error-based" in low or "union query" in low):
        return True
    return False


def _target_urls(base_url: str) -> List[str]:
    base = base_url.rstrip("/")
    return [
        f"{base}/search?q=1",
        f"{base}/posts?sort=id",
        f"{base}/posts?page=1",
    ]


def run_sqlmap(base_url: str, cfg: Dict[str, Any]) -> SqlmapOutcome:
    cfg = cfg or {}
    if not bool(cfg.get("enabled", False)):
        return SqlmapOutcome(ran=False, reason="sqlmap 비활성화(config)")

    binary = str(cfg.get("binary", "sqlmap"))
    if not _is_available(binary):
        return SqlmapOutcome(ran=False, reason=f"sqlmap 미설치({binary})")

    timebox = float(cfg.get("timebox", 60))
    urls = _target_urls(base_url)

    any_injectable = False
    evidence: List[str] = []
    ran_any = False
    for url in urls:
        argv = [
            binary, "-u", url,
            "--batch", "--flush-session",  # non-interactive, reproducible
            "--level", "1", "--risk", "1",
        ]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timebox)
        except subprocess.TimeoutExpired:
            return SqlmapOutcome(
                ran=False,
                reason=f"sqlmap 시간초과({timebox}s)",
                evidence=evidence,
            )
        except Exception as exc:
            return SqlmapOutcome(
                ran=False,
                reason=f"sqlmap 실행 오류({exc})",
                evidence=evidence,
            )
        ran_any = True
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if parse_sqlmap_output(out):
            any_injectable = True
            evidence.append(f"sqlmap {url}: injectable")
            for line in out.strip().splitlines():
                if parse_sqlmap_output(line):
                    evidence.append(f"  ↳ {line.strip()[:160]}")
                    break
            break  # one injectable param is enough

    if not ran_any:
        return SqlmapOutcome(ran=False, reason="sqlmap 대상 URL 없음")

    reason = "sqlmap 인젝션 확인" if any_injectable else "sqlmap 인젝션 미검출"
    return SqlmapOutcome(ran=True, injectable=any_injectable, reason=reason, evidence=evidence)
