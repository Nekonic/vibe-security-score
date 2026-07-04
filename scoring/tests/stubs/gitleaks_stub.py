#!/usr/bin/env python
"""Fake gitleaks: prints a canned findings array (gitleaks JSON is a top-level
list). Surfaces one secret finding so the parse path can be asserted."""
import json
import sys

CANNED = [
    {
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "app.py",
        "StartLine": 23,
        "Secret": "sk-booth-super-secret-do-not-share-123456",
    }
]

if __name__ == "__main__":
    sys.stdout.write(json.dumps(CANNED))
    sys.exit(0)
