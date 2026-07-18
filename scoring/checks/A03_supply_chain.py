"""A03 Software Supply Chain Failures: CVE lookup (local snapshot / OSV-Scanner /
container-resolved recompute), typosquatting, and PyPI-existence checks.

The dependencies pool weight is split across cve + typosquatting by their explicit
sub-weights; that split lives here so the static and dynamic CVE paths agree.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from typing import Dict, List, Optional, Tuple

from ..models import CheckResult
from ..shared.external_tools import (
    _SKIP_DEV, _SKIP_DISABLED, _gate, _run_json, _skipped, _stub_command, _tool_cfg,
)
from .base import Check

try:  # prefer packaging.version for correct comparisons; degrade gracefully
    from packaging.version import Version, InvalidVersion

    _HAVE_PACKAGING = True
except Exception:
    _HAVE_PACKAGING = False


_REPO_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _resolve(path: str) -> str:
    if os.path.isabs(path):
        return path
    return os.path.normpath(os.path.join(_REPO_ROOT, path))


_REQ_LINE = re.compile(
    r"""^\s*
    (?P<name>[A-Za-z0-9._-]+)
    (?:\[[^\]]*\])?
    \s*==\s*
    (?P<version>[A-Za-z0-9._+!-]+)
    """,
    re.VERBOSE,
)


def parse_requirements(text: str) -> List[Tuple[str, str]]:
    """Parse pinned ``name==version`` lines. Non-pinned lines yield (name, "")
    so typosquatting can still inspect them."""
    out: List[Tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _REQ_LINE.match(line)
        if m:
            out.append((m.group("name"), m.group("version")))
            continue
        name_only = re.match(r"^\s*([A-Za-z0-9._-]+)", line)
        if name_only:
            out.append((name_only.group(1), ""))
    return out


def _ver_tuple(v: str) -> Tuple[int, ...]:
    parts = re.split(r"[.\-+]", v)
    nums: List[int] = []
    for p in parts:
        mm = re.match(r"\d+", p)
        nums.append(int(mm.group()) if mm else 0)
    return tuple(nums)


def _ver_lt(a: str, b: str) -> bool:
    if _HAVE_PACKAGING:
        try:
            return Version(a) < Version(b)
        except InvalidVersion:
            pass
    return _ver_tuple(a) < _ver_tuple(b)


def _ver_ge(a: str, b: str) -> bool:
    if _HAVE_PACKAGING:
        try:
            return Version(a) >= Version(b)
        except InvalidVersion:
            pass
    return _ver_tuple(a) >= _ver_tuple(b)


def _in_affected_range(version: str, introduced: str, fixed: Optional[str]) -> bool:
    """introduced <= version < fixed. ``fixed`` None/empty/"0" => unbounded above."""
    if not _ver_ge(version, introduced):
        return False
    if fixed in (None, "", "0"):
        return True
    return _ver_lt(version, fixed)


def _severity_penalties(cve_cfg: dict) -> dict:
    return {
        "critical": float(cve_cfg.get("penalty_critical", 40)),
        "high": float(cve_cfg.get("penalty_high", 25)),
        "medium": float(cve_cfg.get("penalty_medium", 10)),
        "low": float(cve_cfg.get("penalty_low", 3)),
    }


def _match_cve(requirements: List[Tuple[str, str]], dep_cfg: dict) -> CheckResult:
    cve_cfg = dep_cfg.get("cve", {}) or {}
    snapshot_path = _resolve(cve_cfg.get("source", "data/osv_snapshot.json"))
    penalties = _severity_penalties(cve_cfg)

    with open(snapshot_path, "r", encoding="utf-8") as fh:
        snapshot = json.load(fh)
    vulns_by_pkg: Dict[str, list] = {
        k.lower(): v for k, v in snapshot.get("vulnerabilities", {}).items()
    }

    total_penalty = 0.0
    reasons: List[str] = []
    evidence: List[str] = []
    for name, version in requirements:
        if not version:
            continue
        entries = vulns_by_pkg.get(name.lower())
        if not entries:
            continue
        for entry in entries:
            affected = entry.get("affected", {})
            introduced = str(affected.get("introduced", "0"))
            fixed = affected.get("fixed")
            if _in_affected_range(version, introduced, fixed):
                sev = str(entry.get("severity", "medium")).lower()
                pen = penalties.get(sev, penalties["medium"])
                total_penalty += pen
                cve_id = entry.get("id", "UNKNOWN")
                fixed_txt = fixed if fixed else "N/A"
                reasons.append(
                    f"{name}=={version} {cve_id} ({sev}) — {fixed_txt} 에서 수정됨"
                )
                evidence.append(f"{name}=={version}: {cve_id} {entry.get('summary','')}")

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
    )


def levenshtein(a: str, b: str) -> int:
    """Levenshtein edit distance (iterative DP), stdlib-only."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


def _normalize_pkg(name: str) -> str:
    # PyPI treats -, _, . and case as equivalent for names.
    return re.sub(r"[-_.]+", "-", name).lower()


def check_typosquatting(requirements: List[Tuple[str, str]], dep_cfg: dict) -> CheckResult:
    ts_cfg = dep_cfg.get("typosquatting", {}) or {}
    popular_path = _resolve(ts_cfg.get("popular_snapshot", "data/popular_packages.json"))
    max_dist = int(ts_cfg.get("max_edit_distance", 2))
    penalty_per = float(ts_cfg.get("penalty_per_suspect", 50))

    with open(popular_path, "r", encoding="utf-8") as fh:
        popular_raw = json.load(fh).get("packages", [])
    popular = {_normalize_pkg(p) for p in popular_raw}

    total_penalty = 0.0
    reasons: List[str] = []
    evidence: List[str] = []
    for name, _version in requirements:
        norm = _normalize_pkg(name)
        if norm in popular:
            continue
        if len(norm) < 4:
            continue  # short names collide by chance; distance-1 there is noise
        best_name = None
        best_dist = None
        for pop in popular:
            d = levenshtein(norm, pop)
            if best_dist is None or d < best_dist:
                best_dist, best_name = d, pop
        if best_dist is not None and 1 <= best_dist <= max_dist:
            total_penalty += penalty_per
            reasons.append(
                f"{name} — 인기 패키지 '{best_name}'와 편집거리 {best_dist} (오타 스쿼팅 의심)"
            )
            evidence.append(f"{name} ~ {best_name} (dist={best_dist})")

    score = max(0.0, 100.0 - total_penalty)
    return CheckResult(
        check_id="typosquatting",
        category="static",
        label="오타 스쿼팅",
        score=score,
        weight=float(dep_cfg.get("weight", 0)),
        passed=not reasons,
        penalty_reasons=reasons,
        evidence=evidence,
    )


# OSV-Scanner — PRIMARY CVE source, local snapshot as FALLBACK.
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


def check_cve(
    requirements: List[Tuple[str, str]],
    dep_cfg: dict,
    requirements_path: Optional[str],
    config,
    *,
    use_osv: Optional[bool] = None,
) -> CheckResult:
    """CVE check via OSV-Scanner when available, else the local snapshot.
    tool="osv-scanner" when the CLI produced the result; "" for the fallback
    (guaranteeing an offline score identical to the deterministic built-in).

    ``use_osv``: None => honor ``config.skip_static_osv`` (the full grading path
    sets it so the STATIC osv run is skipped — the dynamic pip-freeze recompute
    supersedes it). dynamic_cve passes ``use_osv=True`` to force osv on the
    container's resolved versions regardless of that flag."""
    if use_osv is None:
        use_osv = not getattr(config, "skip_static_osv", False)
    if not use_osv:
        return _match_cve(requirements, dep_cfg)
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
    return _match_cve(requirements, dep_cfg)


def _osv_result_from_data(data: object, dep_cfg: dict) -> Optional[CheckResult]:
    if data is None:
        return None
    cve_cfg = dep_cfg.get("cve", {}) or {}
    penalties = _severity_penalties(cve_cfg)
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


# PyPI existence — hallucinated-package check (opt-in, live network).
def check_hallucinated_package(requirements: List[Tuple[str, str]], config) -> CheckResult:
    tcfg = _tool_cfg(config, "hallucinated_package")
    label = "존재하지 않는 패키지"
    if not bool(tcfg.get("enabled", False)):
        return _skipped("hallucinated_package", label, "pypi", _SKIP_DISABLED)
    if getattr(config, "dev", False):
        return _skipped("hallucinated_package", label, "pypi", _SKIP_DEV)

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


# --- dependencies pool weight split (shared by static + dynamic CVE paths) ---
def _pool_split(dep_cfg: dict, key: str) -> dict:
    """Give the CVE / typosquatting sub-check its own weight, defaulting to an
    even split of the dependencies pool weight."""
    dep_weight = float(dep_cfg.get("weight", 0))
    cfg = dict(dep_cfg)
    cfg["weight"] = float((dep_cfg.get(key) or {}).get("weight", dep_weight / 2.0))
    return cfg


def dynamic_cve(box, config) -> CheckResult:
    """Recompute the CVE check against the container's REAL resolved (transitive)
    package versions from `pip freeze`. In --dev this runs osv-scanner on those
    versions; otherwise the deterministic local snapshot. tool marks it as resolved
    so aggregation prefers it over the requirements-only static result."""
    dep_cfg = _pool_split(dict(config.get("static.dependencies", {}) or {}), "cve")
    freeze = box.pip_freeze()
    requirements = parse_requirements(freeze)
    if not requirements:
        result = _match_cve([], dep_cfg)
        result.tool = "pip-freeze"
        result.label = "의존성 CVE(실측 전이 포함)"
        result.evidence = ["pip freeze 실패 → 정적 requirements 결과 유지"]
        return result

    # Write resolved versions to a temp lockfile so osv-scanner (dev) can scan them.
    tmp = tempfile.NamedTemporaryFile("w", suffix="_requirements.txt", delete=False, encoding="utf-8")
    try:
        tmp.write(freeze)
        tmp.close()
        # Force osv on the RESOLVED versions even when the static path skipped it.
        result = check_cve(requirements, dep_cfg, tmp.name, config, use_osv=True)
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
    result.tool = "pip-freeze" if result.tool != "osv-scanner" else "osv-scanner+freeze"
    result.label = "의존성 CVE(실측 전이 포함)"
    return result


# ── registry entry points ──────────────────────────────────────────────────
# Thin adapters: unpack the StaticContext for the core checks above. cve and
# typosquatting take their weight from the dependencies POOL (via _pool_split, the
# same split the dynamic CVE path uses), so they read config directly instead of the
# runner-passed cfg — the one place a check's weight isn't in its own cfg subtree.
def _cve(check, sctx, cfg):
    dep_cfg = _pool_split(dict(sctx.config.static_dependencies), "cve")
    return check_cve(sctx.requirements, dep_cfg, sctx.requirements_path, sctx.config)


def _typosquatting(check, sctx, cfg):
    dep_cfg = _pool_split(dict(sctx.config.static_dependencies), "typosquatting")
    return check_typosquatting(sctx.requirements, dep_cfg)


def _hallucinated_package(check, sctx, cfg):
    return check_hallucinated_package(sctx.requirements, sctx.config)


CHECKS = [
    Check("cve", "의존성 CVE", "static", _cve),
    Check("typosquatting", "오타 스쿼팅", "static", _typosquatting),
    Check("hallucinated_package", "존재하지 않는 패키지", "static", _hallucinated_package,
          report_only=True),
]
