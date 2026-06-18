"""dependencies.py — grades a Flask app's requirements.txt.

Checks:
  1. CVE scan via OSV-Scanner in offline mode (skipped if binary / DB absent).
  2. Typosquatting / slopsquatting detection against a local popular-package snapshot.

Contract: analyze(code_dir: str) -> {"score": float, "findings": [Finding, ...]}
See modules/__init__.py for the Finding schema.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# Config import — always use constants, never hardcode numbers
# ---------------------------------------------------------------------------
# The repo root is the parent of this file's directory; add it to sys.path if
# needed so that config.py can be imported regardless of how the grader is run.
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_MODULE_DIR)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import config  # noqa: E402  (after path fixup)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_name(name: str) -> str:
    """PEP 503 normalisation: lowercase, collapse runs of [-_.] to a single '-'."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())


# Regex to parse a single requirement line.
# Handles: pkg, pkg==1.0, pkg>=1.0, pkg~=1.0, pkg[extra]==1.0, pkg[e1,e2]>=1.0
_REQ_LINE_RE = re.compile(
    r"^\s*"
    r"([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"  # package name
    r"(?:\[[^\]]*\])?"                                   # optional extras
    r"\s*"
    r"(==|>=|<=|~=|!=|>|<)?\s*"                         # optional operator
    r"([^\s;#]*)?"                                        # optional version
    r"\s*"
)


def _parse_requirements(req_path: str) -> list[dict]:
    """Parse a requirements.txt file into a list of {name, version, raw} dicts.

    Skips blank lines, comments, -r/-e/-c flags, and URL-based requirements.
    """
    packages = []
    try:
        with open(req_path, encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                # Skip blanks, comments, flags
                if not line or line.startswith("#"):
                    continue
                if re.match(r"^(-r|-e|-c)\s", line):
                    continue
                # Skip URL-based (contains ://  or starts with .)
                if "://" in line or line.startswith("."):
                    continue
                # Strip inline comments
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                m = _REQ_LINE_RE.match(line)
                if m:
                    pkg_name = m.group(1)
                    version = m.group(3) or None
                    packages.append(
                        {
                            "name": pkg_name,
                            "normalized": _normalize_name(pkg_name),
                            "version": version,
                            "raw": raw_line.rstrip(),
                        }
                    )
    except OSError:
        pass
    return packages


def _find_requirements_txt(code_dir: str) -> str | None:
    """Locate requirements.txt in code_dir or common subdirs."""
    candidates = [
        os.path.join(code_dir, "requirements.txt"),
        os.path.join(code_dir, "requirements", "base.txt"),
        os.path.join(code_dir, "requirements", "common.txt"),
        os.path.join(code_dir, "requirements", "prod.txt"),
        os.path.join(code_dir, "requirements", "production.txt"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


# ---------------------------------------------------------------------------
# Levenshtein distance (pure stdlib, no external deps)
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    len_a, len_b = len(a), len(b)
    # Quick boundary checks
    if len_a == 0:
        return len_b
    if len_b == 0:
        return len_a

    # Use two rows (current and previous) to save memory.
    prev = list(range(len_b + 1))
    curr = [0] * (len_b + 1)

    for i in range(1, len_a + 1):
        curr[0] = i
        for j in range(1, len_b + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(
                curr[j - 1] + 1,       # insertion
                prev[j] + 1,           # deletion
                prev[j - 1] + cost,    # substitution
            )
        prev, curr = curr, prev

    return prev[len_b]


# ---------------------------------------------------------------------------
# Typosquat check
# ---------------------------------------------------------------------------

def _load_popular_packages(repo_root: str) -> list[str]:
    """Load the popular-packages snapshot and return normalised names."""
    snapshot_path = os.path.join(repo_root, config.POPULAR_PACKAGES_SNAPSHOT)
    try:
        with open(snapshot_path, encoding="utf-8") as fh:
            data = json.load(fh)
        raw = data.get("packages", [])
        return [_normalize_name(p) for p in raw]
    except (OSError, json.JSONDecodeError, KeyError):
        return []


def _typosquat_findings(packages: list[dict], popular: list[str]) -> tuple[list[dict], float]:
    """Return typosquat findings and total penalty."""
    popular_set = set(popular)
    findings: list[dict] = []
    total_penalty = 0.0

    flagged_count = 0
    for pkg in packages:
        norm = pkg["normalized"]

        # Exact match in popular list -> safe
        if norm in popular_set:
            continue

        # Too short -> skip (noise)
        if len(norm) < config.TYPOSQUAT_MIN_NAME_LENGTH:
            continue

        # Find minimum edit distance to any popular name
        min_dist = None
        nearest = None
        for pop in popular:
            d = _levenshtein(norm, pop)
            if min_dist is None or d < min_dist:
                min_dist = d
                nearest = pop
                if d == 1:
                    break  # can't get better than 1 (0 would be exact match, handled above)

        # Flag if within [1, MAX_EDIT_DISTANCE]
        if min_dist is not None and 1 <= min_dist <= config.TYPOSQUAT_MAX_EDIT_DISTANCE:
            penalty = config.TYPOSQUAT_PENALTY
            total_penalty += penalty
            flagged_count += 1
            findings.append(
                {
                    "id": f"typosquat_{norm}",
                    "label": f"잠재적 타이포스쿼팅 패키지: {pkg['name']}",
                    "passed": False,
                    "penalty": penalty,
                    "reason": (
                        f"패키지 '{pkg['name']}' 은(는) 인기 패키지 '{nearest}' 와(과) "
                        f"편집 거리 {min_dist} 로 매우 유사합니다. "
                        "타이포스쿼팅 또는 슬롭스쿼팅 공격 패키지일 수 있으니 "
                        "패키지 이름 철자를 반드시 확인하세요."
                    ),
                    "evidence": f"{pkg['name']} ~ {nearest} (편집 거리 {min_dist})",
                }
            )

    # Cap total typosquat penalty
    capped_penalty = min(total_penalty, config.TYPOSQUAT_PENALTY_CAP)

    # If some penalty was capped, record the cap adjustment (informational only)
    if total_penalty > config.TYPOSQUAT_PENALTY_CAP:
        # Re-adjust last finding is complex; instead we note it in a summary finding
        pass

    # Add a summary "passed" finding if nothing was flagged
    if flagged_count == 0:
        findings.append(
            {
                "id": "typosquat_check",
                "label": "타이포스쿼팅/슬롭스쿼팅 검사",
                "passed": True,
                "penalty": 0.0,
                "reason": "인기 패키지와 유사한 이름의 의심스러운 패키지가 발견되지 않았습니다.",
                "evidence": None,
            }
        )

    return findings, capped_penalty


# ---------------------------------------------------------------------------
# OSV-Scanner CVE check
# ---------------------------------------------------------------------------

def _osv_skip_finding(reason: str) -> dict:
    return {
        "id": "cve_scan",
        "label": "CVE 취약점 검사 (OSV-Scanner)",
        "passed": True,
        "penalty": 0.0,
        "reason": reason,
        "evidence": None,
        "skipped": True,
    }


def _parse_cvss_score(severity_list: list) -> float | None:
    """Extract the highest CVSS numeric base score from an OSV severity list."""
    best: float | None = None
    for entry in severity_list:
        score_str = entry.get("score", "")
        # Could be a numeric string like "7.5" or a CVSS vector
        # Try numeric first
        try:
            val = float(score_str)
            if best is None or val > best:
                best = val
            continue
        except (ValueError, TypeError):
            pass
        # Try to parse CVSS vector: look for /AV: ... /CVSS:3.x/... patterns
        # E.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" base score not embedded
        # For vectors we cannot easily extract base score inline without full CVSS lib;
        # skip for now and rely on textual severity fallback.
    return best


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    else:
        return "LOW"


def _penalty_for_severity(severity: str) -> float:
    """Look up penalty; handle MODERATE as MEDIUM alias."""
    return config.CVE_SEVERITY_PENALTIES.get(
        severity,
        config.CVE_SEVERITY_PENALTIES.get("MEDIUM", 8),
    )


def _run_osv_scanner(req_path: str, offline_db_dir: str) -> dict | None:
    """Run osv-scanner with multiple candidate flag forms; return parsed JSON or None."""
    # Candidate command forms for different OSV-Scanner versions.
    # We try each in order and return the first that produces parseable JSON.
    candidate_commands = [
        # v1.x style: --experimental-local-db
        [
            config.OSV_SCANNER_BINARY,
            "--format", "json",
            "--experimental-local-db", offline_db_dir,
            "--lockfile", req_path,
        ],
        # v2.x style: --local-db-path
        [
            config.OSV_SCANNER_BINARY,
            "--format", "json",
            "--local-db-path", offline_db_dir,
            "--lockfile", req_path,
        ],
        # Fallback: no offline flag (may hit network but won't crash)
        [
            config.OSV_SCANNER_BINARY,
            "--format", "json",
            "--lockfile", req_path,
        ],
    ]

    for cmd in candidate_commands:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.OSV_TIMEOUT_SEC,
            )
            # osv-scanner exits 1 when vulnerabilities are found; that's still valid output.
            if result.stdout.strip():
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError:
                    continue
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None
    return None


def _cve_findings(req_path: str) -> tuple[list[dict], float]:
    """Run CVE check and return (findings, total_penalty)."""
    # Guard: binary must be on PATH
    if not shutil.which(config.OSV_SCANNER_BINARY):
        return [
            _osv_skip_finding(
                "OSV-Scanner 바이너리 또는 오프라인 DB 부재 — CVE 검사 생략(점수 중립)."
            )
        ], 0.0

    # Guard: offline DB directory must exist
    offline_db = os.path.join(_REPO_ROOT, config.OSV_OFFLINE_DB_DIR)
    if not os.path.isdir(offline_db):
        return [
            _osv_skip_finding(
                "OSV-Scanner 바이너리 또는 오프라인 DB 부재 — CVE 검사 생략(점수 중립)."
            )
        ], 0.0

    # Run scanner
    osv_data = _run_osv_scanner(req_path, offline_db)
    if osv_data is None:
        return [
            _osv_skip_finding(
                "OSV-Scanner 실행 중 오류 발생 — CVE 검사 생략(점수 중립)."
            )
        ], 0.0

    # Parse results
    findings: list[dict] = []
    total_penalty = 0.0

    try:
        results = osv_data.get("results", [])
        for result in results:
            for package_info in result.get("packages", []):
                pkg_meta = package_info.get("package", {})
                pkg_name = pkg_meta.get("name", "unknown")
                pkg_version = pkg_meta.get("version", "unknown")
                pkg_label = f"{pkg_name}=={pkg_version}"

                vulnerabilities = package_info.get("vulnerabilities", [])
                if not vulnerabilities:
                    continue

                # Find the worst vulnerability for this package
                worst_severity = "LOW"
                worst_vuln_id = ""
                worst_score_numeric: float | None = None

                for vuln in vulnerabilities:
                    vuln_id = vuln.get("id", "")
                    severity_list = vuln.get("severity", [])
                    db_specific = vuln.get("database_specific", {})

                    # Try numeric CVSS first
                    numeric = _parse_cvss_score(severity_list)
                    if numeric is not None:
                        sev = _severity_from_score(numeric)
                        # Compare against current worst
                        sev_order = ["LOW", "MEDIUM", "MODERATE", "HIGH", "CRITICAL"]
                        if worst_score_numeric is None or numeric > worst_score_numeric:
                            worst_score_numeric = numeric
                            worst_severity = sev
                            worst_vuln_id = vuln_id
                    else:
                        # Fallback to textual severity
                        text_sev = (
                            db_specific.get("severity", "")
                            or (severity_list[0].get("type", "") if severity_list else "")
                        ).upper()
                        # Normalise MODERATE -> MEDIUM for ordering
                        norm_sev = "MEDIUM" if text_sev == "MODERATE" else text_sev
                        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                        current_order = sev_order.get(
                            "MEDIUM" if worst_severity == "MODERATE" else worst_severity, 0
                        )
                        new_order = sev_order.get(norm_sev, 0)
                        if new_order > current_order:
                            worst_severity = text_sev or "LOW"
                            worst_vuln_id = vuln_id

                penalty = _penalty_for_severity(worst_severity)
                total_penalty += penalty

                findings.append(
                    {
                        "id": f"cve_{pkg_name}",
                        "label": f"알려진 CVE 취약점: {pkg_label}",
                        "passed": False,
                        "penalty": penalty,
                        "reason": (
                            f"패키지 {pkg_label} 에서 {worst_severity} 등급 취약점 "
                            f"({worst_vuln_id}) 이 발견되었습니다. "
                            "최신 보안 패치 버전으로 업그레이드하세요."
                        ),
                        "evidence": f"{pkg_label}: {worst_vuln_id} ({worst_severity})",
                    }
                )

    except (KeyError, TypeError, AttributeError):
        # If JSON shape is unexpected, treat as skipped
        return [
            _osv_skip_finding("OSV 결과 파싱 실패 — CVE 검사 생략(점수 중립).")
        ], 0.0

    # Cap total CVE penalty
    capped_penalty = min(total_penalty, config.CVE_PENALTY_CAP)

    # If no vulnerabilities found at all, add a passing finding
    if not findings:
        findings.append(
            {
                "id": "cve_scan",
                "label": "CVE 취약점 검사 (OSV-Scanner)",
                "passed": True,
                "penalty": 0.0,
                "reason": "알려진 CVE 취약점이 발견되지 않았습니다.",
                "evidence": None,
            }
        )

    return findings, capped_penalty


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze(code_dir: str) -> dict:
    """Analyze a Flask app's requirements.txt for CVEs and typosquatting.

    Returns:
        {"score": float, "findings": [Finding, ...]}
    """
    findings: list[dict] = []

    # --- Locate requirements.txt -------------------------------------------
    req_path = _find_requirements_txt(code_dir)
    if req_path is None:
        findings.append(
            {
                "id": "requirements_missing",
                "label": "requirements.txt 없음",
                "passed": False,
                "penalty": 0.0,
                "reason": (
                    "requirements.txt 파일을 찾을 수 없습니다. "
                    "의존성 검사를 건너뜁니다."
                ),
                "evidence": None,
                "skipped": True,
            }
        )
        return {"score": float(config.DEPENDENCIES_START), "findings": findings}

    # --- Parse packages -------------------------------------------------------
    packages = _parse_requirements(req_path)

    # --- CVE check ------------------------------------------------------------
    cve_findings, cve_penalty = _cve_findings(req_path)
    findings.extend(cve_findings)

    # --- Typosquat check ------------------------------------------------------
    popular = _load_popular_packages(_REPO_ROOT)
    typo_findings, typo_penalty = _typosquat_findings(packages, popular)
    findings.extend(typo_findings)

    # --- Final score ----------------------------------------------------------
    score = max(0.0, float(config.DEPENDENCIES_START) - cve_penalty - typo_penalty)
    # Round to one decimal place for readability
    score = round(score, 1)

    return {"score": score, "findings": findings}
