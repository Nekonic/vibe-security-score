#!/usr/bin/env python
"""Fake osv-scanner: prints canned OSV JSON, exits 1 (as the real one does when
vulnerabilities are found). Used to exercise the parse path without installing
the real tool. Reports one CRITICAL vuln for the fictional package 'evilpkg'."""
import sys

CANNED = {
    "results": [
        {
            "packages": [
                {
                    "package": {"name": "evilpkg", "version": "1.0.0"},
                    "vulnerabilities": [
                        {
                            "id": "OSV-STUB-CRITICAL",
                            "database_specific": {"severity": "CRITICAL"},
                        }
                    ],
                }
            ]
        }
    ]
}

if __name__ == "__main__":
    import json

    sys.stdout.write(json.dumps(CANNED))
    sys.exit(1)  # osv-scanner exits non-zero when it finds vulns
