#!/usr/bin/env python
"""Fake semgrep: prints canned {"results": [...]} JSON with one security finding."""
import json
import sys

CANNED = {
    "results": [
        {
            "check_id": "python.flask.security.audit.debug-enabled",
            "path": "app.py",
            "start": {"line": 156},
            "extra": {"message": "Flask app run with debug=True"},
        }
    ]
}

if __name__ == "__main__":
    sys.stdout.write(json.dumps(CANNED))
    sys.exit(0)
