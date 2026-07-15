"""Subprocess/JSON plumbing shared by the optional external-tool checks.

Every tool is OPTIONAL: if its binary is missing or config disables it, the
caller SKIPs (emits skipped=True) or report-only (weight 0) — never crashes. The
deterministic score is identical whether or not these tools are present.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import List, Optional, Tuple

from ..models import CheckResult

_SKIP_REASON = "검사 생략(도구 미설치)"
_SKIP_DISABLED = "검사 생략(도구 비활성화)"
_SKIP_DEV = "검사 생략(--dev: 내장 검사 사용, 외부 도구 미실행)"

# External tools required in the DEFAULT (non-dev) mode. --dev uses the built-in
# checks instead and does NOT require these.
_REQUIRED_TOOLS = ("osv_scanner", "gitleaks", "semgrep", "sqlmap")


def _tool_cfg(config, name: str) -> dict:
    return (config.get(f"tools.{name}", {}) or {})


def missing_required_tools(config) -> List[str]:
    """Enabled external tools whose binary is not installed. Empty in --dev
    (built-in checks are used and no tool is required)."""
    if getattr(config, "dev", False):
        return []
    missing: List[str] = []
    for name in _REQUIRED_TOOLS:
        tcfg = _tool_cfg(config, name)
        if bool(tcfg.get("enabled", False)) and not resolve_binary(tcfg.get("binary", name)):
            missing.append(str(tcfg.get("binary", name)))
    return missing


def _gate(config, name: str) -> Tuple[Optional[str], Optional[str]]:
    """Return (bin_path, skip_reason). Default: use the installed external tool
    (a preflight check aborts earlier if it is missing). --dev: don't use the tool
    at all — the caller falls back to the built-in check."""
    tcfg = _tool_cfg(config, name)
    if not bool(tcfg.get("enabled", False)):
        return None, _SKIP_DISABLED
    if getattr(config, "dev", False):
        return None, _SKIP_DEV
    bin_path = resolve_binary(tcfg.get("binary", name))
    if bin_path:
        return bin_path, None
    return None, _SKIP_REASON  # normally unreachable (preflight blocks this)


def resolve_binary(binary: str) -> Optional[str]:
    """Absolute path to ``binary`` if runnable, else None. Accepts a bare command
    on PATH or a direct path to a file (test stub scripts)."""
    if not binary:
        return None
    if os.path.sep in binary or (os.path.altsep and os.path.altsep in binary):
        return binary if os.path.isfile(binary) else None
    return shutil.which(binary)


def _skipped(check_id: str, label: str, tool: str, reason: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        category="static",
        label=label,
        score=0.0,
        weight=0.0,
        passed=True,  # skipped => excluded from scoring
        penalty_reasons=[reason],
        evidence=[],
        skipped=True,
        tool=tool,
    )


def _run_json(cmd: List[str], timeout: float, cwd: Optional[str] = None) -> Optional[object]:
    """Run ``cmd`` and parse stdout as JSON. None on any failure. A non-zero exit
    is NOT an error as long as stdout parses (osv-scanner exits non-zero on finds)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    out = (proc.stdout or "").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return None


def _stub_command(bin_path: str) -> List[str]:
    # .py fake binaries get the current interpreter prepended (cross-platform).
    import sys

    if bin_path.lower().endswith(".py"):
        return [sys.executable, bin_path]
    return [bin_path]
