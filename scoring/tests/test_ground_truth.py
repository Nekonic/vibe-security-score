"""Ground-truth regression: grade real generated apps and compare every verdict with
an independent red-team audit (fixtures/ground_truth/*.json — each VULNERABLE
verdict there was confirmed by a working exploit, each SAFE one by a failed attack;
notes in research_notes/redteam-ground-truth/).

Rules per check:
  truth VULNERABLE -> grader must fail it            (a pass or a skip is a miss)
  truth SAFE       -> grader must not fail it        (skip allowed: e.g. no internet
                                                      for the SSRF positive control)
  truth N/A        -> grader must not fail it

Docker integration (each app boots in the sandbox, ~30s); skipped without Docker.
Runs in --dev so it doesn't depend on host-installed scanners.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from scoring import grade_submission
from scoring.config import load_config

_HERE = os.path.dirname(__file__)
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, "..", ".."))
_TRUTH_DIR = os.path.join(_HERE, "fixtures", "ground_truth")


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _docker_available(), reason="docker CLI/daemon unavailable")


def _truths():
    for name in sorted(os.listdir(_TRUTH_DIR)):
        if name.endswith(".json"):
            with open(os.path.join(_TRUTH_DIR, name), encoding="utf-8") as fh:
                yield json.load(fh)


_TRUTHS = list(_truths())


def _containers():
    out = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True, timeout=20).stdout
    return set(out.split())


@pytest.fixture(scope="module", params=_TRUTHS, ids=[t["app"] for t in _TRUTHS])
def graded(request):
    truth = request.param
    config = load_config()
    config.dev = True
    before = _containers()
    report = grade_submission(f"gt-{truth['app']}", os.path.join(_REPO_ROOT, truth["path"]), config)
    leaked = _containers() - before
    verdicts = {}
    for f in report["findings"]:
        verdicts[f["check_id"]] = "SKIP" if f["skipped"] else ("SAFE" if f["passed"] else "VULNERABLE")
    return truth, verdicts, report, leaked


def test_boots_and_passes_functional_gate(graded):
    _truth, _verdicts, report, _ = graded
    assert report["boot_failed"] is False
    assert report["functional_failed"] is False, report["boot_log"]
    # CVEs are re-measured on the container's resolved (pip freeze) versions.
    cve = next(f for f in report["findings"] if f["check_id"] == "cve")
    assert "freeze" in cve["tool"]


# Checks that must decide on every fixture: a skip there is a regression, not the
# allowed "no internet" skip of a SAFE SSRF control.
_MUST_DECIDE = {"idor_write"}


def test_verdicts_match_red_team(graded):
    truth, verdicts, _report, _ = graded
    problems = []
    for cid, expected in truth["verdicts"].items():
        got = verdicts.get(cid)
        if got is None:
            problems.append(f"{cid}: grader produced no verdict")
        elif got == "SKIP" and cid in _MUST_DECIDE:
            problems.append(f"{cid}: skipped (undecidable) — red team: {truth['why'].get(cid, '')}")
        elif expected == "VULNERABLE" and got != "VULNERABLE":
            problems.append(f"{cid}: missed (FN) — red team: {truth['why'].get(cid, '')}")
        elif expected in ("SAFE", "N/A") and got == "VULNERABLE":
            problems.append(f"{cid}: false positive — red team: {truth['why'].get(cid, '')}")
    assert not problems, f"{truth['app']}:\n  " + "\n  ".join(problems)


def test_no_containers_left_behind(graded):
    *_, leaked = graded
    assert not leaked, f"containers left running: {leaked}"
