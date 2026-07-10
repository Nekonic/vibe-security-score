"""Dependency static checks: requirements parsing, CVE lookup, typosquatting.

Thresholds come from config (static.dependencies.*); snapshots from the JSON
files named in config, resolved relative to the repo root.
"""
from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Tuple

from ..models import CheckResult

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


def check_cve(requirements: List[Tuple[str, str]], dep_cfg: dict) -> CheckResult:
    cve_cfg = dep_cfg.get("cve", {}) or {}
    snapshot_path = _resolve(cve_cfg.get("source", "data/osv_snapshot.json"))
    penalties = {
        "critical": float(cve_cfg.get("penalty_critical", 40)),
        "high": float(cve_cfg.get("penalty_high", 25)),
        "medium": float(cve_cfg.get("penalty_medium", 10)),
        "low": float(cve_cfg.get("penalty_low", 3)),
    }

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
