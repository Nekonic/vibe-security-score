"""Unit tests for the optional sqlmap wrapper — NO docker, NO real sqlmap.

Covers:
  * parse of canned sqlmap "injectable" output,
  * the stub-binary path: point tools.sqlmap.binary at a tiny script that emits
    canned sqlmap output and assert run_sqlmap parses it to injectable=True,
  * disabled/absent => ran=False (caller falls back), never crashes.
"""
from __future__ import annotations

import os
import stat
import sys
import textwrap

from scoring.dynamic import sqlmap as sqlmap_tool


# Canned sqlmap "injectable" transcript fragment.
_CANNED_INJECTABLE = textwrap.dedent(
    """
    [INFO] testing connection to the target URL
    [INFO] GET parameter 'q' appears to be 'AND boolean-based blind' injectable
    sqlmap identified the following injection point(s) with a total of 42 HTTP(s) requests:
    ---
    Parameter: q (GET)
        Type: boolean-based blind
        Title: AND boolean-based blind - WHERE or HAVING clause
        Payload: q=1' AND 1=1 -- -
    ---
    [INFO] the back-end DBMS is SQLite
    """
).strip()

_CANNED_CLEAN = textwrap.dedent(
    """
    [INFO] testing connection to the target URL
    [WARNING] GET parameter 'q' does not seem to be injectable
    [INFO] all tested parameters do not appear to be injectable.
    """
).strip()


def test_parse_injectable_output():
    assert sqlmap_tool.parse_sqlmap_output(_CANNED_INJECTABLE) is True


def test_parse_clean_output():
    assert sqlmap_tool.parse_sqlmap_output(_CANNED_CLEAN) is False


def test_disabled_falls_back():
    outcome = sqlmap_tool.run_sqlmap("http://127.0.0.1:5000", {"enabled": False, "binary": "sqlmap"})
    assert outcome.ran is False
    assert outcome.injectable is False


def test_missing_binary_falls_back():
    outcome = sqlmap_tool.run_sqlmap(
        "http://127.0.0.1:5000",
        {"enabled": True, "binary": "definitely-not-a-real-binary-xyz"},
    )
    assert outcome.ran is False


def _write_stub(tmp_path, body_after_shebang: str, name: str) -> str:
    """Write a tiny executable stub script and return its path.

    On Windows we can't rely on a shebang, so we emit a .py stub and invoke it
    via the current interpreter through a small launcher; but sqlmap wrapper
    calls the binary directly, so we write a platform-appropriate stub.
    """
    if sys.platform.startswith("win"):
        # A .cmd wrapper that shells out to python printing the canned output.
        py = os.path.join(str(tmp_path), name + "_impl.py")
        with open(py, "w", encoding="utf-8") as fh:
            fh.write("import sys\nsys.stdout.write('''" + body_after_shebang + "''')\n")
        cmd = os.path.join(str(tmp_path), name + ".cmd")
        with open(cmd, "w", encoding="utf-8") as fh:
            fh.write(f'@echo off\r\n"{sys.executable}" "{py}" %*\r\n')
        return cmd
    else:
        sh = os.path.join(str(tmp_path), name)
        with open(sh, "w", encoding="utf-8") as fh:
            fh.write("#!/bin/sh\ncat <<'EOF'\n" + body_after_shebang + "\nEOF\n")
        os.chmod(sh, os.stat(sh).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
        return sh


def test_stub_binary_injectable(tmp_path):
    stub = _write_stub(tmp_path, _CANNED_INJECTABLE, "sqlmap_stub_inj")
    outcome = sqlmap_tool.run_sqlmap(
        "http://127.0.0.1:5000",
        {"enabled": True, "binary": stub, "timebox": 30},
    )
    assert outcome.ran is True
    assert outcome.injectable is True
    assert any("injectable" in e for e in outcome.evidence)


def test_stub_binary_clean(tmp_path):
    stub = _write_stub(tmp_path, _CANNED_CLEAN, "sqlmap_stub_clean")
    outcome = sqlmap_tool.run_sqlmap(
        "http://127.0.0.1:5000",
        {"enabled": True, "binary": stub, "timebox": 30},
    )
    assert outcome.ran is True
    assert outcome.injectable is False
