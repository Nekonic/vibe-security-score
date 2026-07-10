"""Optional external-tool integrations for the STATIC half.

Every tool is OPTIONAL: if its binary is missing or config disables it, we SKIP
(emit skipped=True) or report-only (weight 0) — never crash. The deterministic
score is identical whether or not these tools are present.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from ..models import CheckResult
from . import dependency_checks as dc

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


def _skipped_check(check_id: str, label: str, tool: str, reason: str) -> CheckResult:
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


# 1. OSV-Scanner — PRIMARY CVE source, local snapshot as FALLBACK.
_SEV_ALIASES = {
    "critical": "critical",
    "high": "high",
    "moderate": "medium",
    "medium": "medium",
    "low": "low",
}


def _map_severity(raw: str) -> str:
    return _SEV_ALIASES.get(str(raw or "").lower(), "medium")


_SEV_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _parse_osv_output(data: object) -> List[Tuple[str, str, str, str]]:
    """Extract (pkg, version, cve_id, severity) tuples from osv-scanner JSON.

    De-duplicated by (package, advisory id): osv-scanner can list the same
    advisory more than once (multiple lockfile entries, or a GHSA + its CVE
    alias), and double-penalising one CVE is unfair/indefensible. Keeps the
    highest severity seen for each (package, id)."""
    seen: Dict[Tuple[str, str], Tuple[str, str, str, str]] = {}
    order: List[Tuple[str, str]] = []
    if not isinstance(data, dict):
        return []
    for result in data.get("results", []) or []:
        for pkg in (result.get("packages", []) or []):
            pinfo = pkg.get("package", {}) or {}
            name = pinfo.get("name", "")
            version = pinfo.get("version", "")
            for vuln in (pkg.get("vulnerabilities", []) or []):
                cve_id = vuln.get("id", "UNKNOWN")
                sev = _extract_osv_severity(vuln, pkg)
                key = (name.lower(), cve_id)
                prev = seen.get(key)
                if prev is None:
                    seen[key] = (name, version, cve_id, sev)
                    order.append(key)
                elif _SEV_RANK.get(sev, 1) > _SEV_RANK.get(prev[3], 1):
                    seen[key] = (name, version, cve_id, sev)  # keep worst severity
    return [seen[k] for k in order]


def _extract_osv_severity(vuln: dict, pkg: dict) -> str:
    dbs = vuln.get("database_specific", {}) or {}
    if dbs.get("severity"):
        return _map_severity(dbs["severity"])
    for group in (pkg.get("groups", []) or []):
        if group.get("max_severity"):
            return _map_severity(_cvss_bucket(group["max_severity"]))
    for sv in (vuln.get("severity", []) or []):
        score = sv.get("score", "")
        if score and str(score).replace(".", "", 1).isdigit():
            return _cvss_bucket(score)
    return "medium"


def _cvss_bucket(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    return "low"


def check_cve_with_osv(
    requirements: List[Tuple[str, str]],
    dep_cfg: dict,
    requirements_path: Optional[str],
    config,
) -> CheckResult:
    """CVE check via OSV-Scanner when available, else the local snapshot.
    tool="osv-scanner" when the CLI produced the result; "" for the fallback
    (guaranteeing an offline score identical to the deterministic built-in)."""
    tcfg = _tool_cfg(config, "osv_scanner")
    bin_path, _skip = _gate(config, "osv_scanner")

    if bin_path and requirements_path and os.path.isfile(requirements_path):
        cmd = _stub_command(bin_path) + [
            "--format", "json",
            "--lockfile", f"requirements.txt:{requirements_path}",
        ]
        data = _run_json(cmd, float(tcfg.get("timeout", 60)))
        result = _osv_result_from_data(data, dep_cfg)
        if result is not None:
            return result

    # Default / fallback: deterministic local snapshot (offline, reproducible).
    return dc.check_cve(requirements, dep_cfg)


def _osv_result_from_data(data: object, dep_cfg: dict) -> Optional[CheckResult]:
    if data is None:
        return None
    cve_cfg = dep_cfg.get("cve", {}) or {}
    penalties = {
        "critical": float(cve_cfg.get("penalty_critical", 40)),
        "high": float(cve_cfg.get("penalty_high", 25)),
        "medium": float(cve_cfg.get("penalty_medium", 10)),
        "low": float(cve_cfg.get("penalty_low", 3)),
    }
    findings = _parse_osv_output(data)
    total_penalty = 0.0
    reasons: List[str] = []
    evidence: List[str] = []
    for name, version, cve_id, sev in findings:
        pen = penalties.get(sev, penalties["medium"])
        total_penalty += pen
        pinned = f"{name}=={version}" if version else name
        reasons.append(f"{pinned} {cve_id} ({sev})")
        evidence.append(f"{pinned}: {cve_id}")

    score = max(0.0, 100.0 - total_penalty)
    return CheckResult(
        check_id="cve",
        category="static",
        label="의존성 CVE",
        score=score,
        weight=float(dep_cfg.get("weight", 0)),
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
        tool="osv-scanner",
    )


# 2. gitleaks — hardcoded-secret corroboration (report-only, weight 0).
def check_gitleaks(app_dir: str, config) -> CheckResult:
    tcfg = _tool_cfg(config, "gitleaks")
    label = "시크릿 스캔(gitleaks)"
    bin_path, skip = _gate(config, "gitleaks")
    if bin_path is None:
        return _skipped_check("gitleaks_secrets", label, "gitleaks", skip or _SKIP_REASON)

    cmd = _stub_command(bin_path) + [
        "detect", "--no-git", "--report-format", "json",
        "--report-path", "/dev/stdout", "--source", app_dir,
    ]
    data = _run_json(cmd, float(tcfg.get("timeout", 60)))
    if data is None:
        data = []  # ran but nothing parseable => treat as clean

    reasons, evidence = _parse_gitleaks(data)
    return CheckResult(
        check_id="gitleaks_secrets",
        category="static",
        label=label,
        score=0.0 if reasons else 100.0,
        weight=0.0,
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
        skipped=False,
        tool="gitleaks",
    )


def _parse_gitleaks(data: object) -> Tuple[List[str], List[str]]:
    reasons: List[str] = []
    evidence: List[str] = []
    findings = data if isinstance(data, list) else data.get("findings", []) if isinstance(data, dict) else []
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        rule = f.get("RuleID") or f.get("Description") or "secret"
        file_ = f.get("File", "")
        line = f.get("StartLine", "")
        loc = f"{file_}:{line}" if file_ else ""
        reasons.append(f"{loc} {rule} 시크릿 탐지".strip())
        secret = f.get("Secret", "")
        evidence.append(f"{loc}: {rule} {secret}".strip())
    return reasons, evidence


# 3. semgrep — auxiliary security findings (report-only, weight 0).
def check_semgrep(app_dir: str, config) -> CheckResult:
    tcfg = _tool_cfg(config, "semgrep")
    label = "정적 룰셋(semgrep)"
    bin_path, skip = _gate(config, "semgrep")
    if bin_path is None:
        return _skipped_check("semgrep", label, "semgrep", skip or _SKIP_REASON)

    ruleset = tcfg.get("ruleset", "p/security-audit")
    cmd = _stub_command(bin_path) + ["--config", ruleset, "--json", "--quiet", app_dir]
    data = _run_json(cmd, float(tcfg.get("timeout", 120)))
    if data is None:
        data = {"results": []}

    reasons, evidence = _parse_semgrep(data)
    return CheckResult(
        check_id="semgrep",
        category="static",
        label=label,
        score=0.0 if reasons else 100.0,
        weight=0.0,
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
        skipped=False,
        tool="semgrep",
    )


def _parse_semgrep(data: object) -> Tuple[List[str], List[str]]:
    reasons: List[str] = []
    evidence: List[str] = []
    if not isinstance(data, dict):
        return reasons, evidence
    for r in (data.get("results", []) or []):
        if not isinstance(r, dict):
            continue
        check_id = r.get("check_id", "semgrep-rule")
        path = r.get("path", "")
        start = (r.get("start", {}) or {}).get("line", "")
        loc = f"{path}:{start}" if path else ""
        msg = (r.get("extra", {}) or {}).get("message", "") or check_id
        reasons.append(f"{loc} {check_id}".strip())
        evidence.append(f"{loc}: {msg}".strip())
    return reasons, evidence


# 4. PyPI existence — hallucinated-package check (opt-in, live network).
def check_pypi_existence(requirements: List[Tuple[str, str]], config) -> CheckResult:
    tcfg = _tool_cfg(config, "pypi_existence")
    label = "존재하지 않는 패키지"
    if not bool(tcfg.get("enabled", False)):
        return _skipped_check("hallucinated_package", label, "pypi", _SKIP_DISABLED)
    if getattr(config, "dev", False):
        return _skipped_check("hallucinated_package", label, "pypi", _SKIP_DEV)

    index_url = tcfg.get("index_url", "https://pypi.org/pypi/{package}/json")
    timeout = float(tcfg.get("timeout", 8))
    penalty_per_missing = float(tcfg.get("penalty_per_missing", 40))

    missing = _find_missing_packages(requirements, index_url, timeout)
    reasons = [f"{name} — PyPI에 존재하지 않는 패키지(환각 의심)" for name in missing]
    evidence = list(missing)
    score = max(0.0, 100.0 - penalty_per_missing * len(missing))
    return CheckResult(
        check_id="hallucinated_package",
        category="static",
        label=label,
        score=score,
        weight=0.0,
        passed=not missing,
        penalty_reasons=reasons,
        evidence=evidence,
        skipped=False,
        tool="pypi",
    )


def _find_missing_packages(
    requirements: List[Tuple[str, str]], index_url: str, timeout: float
) -> List[str]:
    import urllib.error
    import urllib.request

    missing: List[str] = []
    seen: Dict[str, bool] = {}
    for name, _version in requirements:
        if not name or name in seen:
            continue
        seen[name] = True
        url = index_url.format(package=name)
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                if getattr(resp, "status", 200) == 404:
                    missing.append(name)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                missing.append(name)
        except (urllib.error.URLError, OSError):
            # network failure => inconclusive, never penalize
            continue
    return missing
