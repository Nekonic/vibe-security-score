"""Root conftest.py — makes the repo importable regardless of CWD."""
import os
import sys

# Always put the repo root first so `import config` and `from modules import ...` work.
sys.path.insert(0, os.path.dirname(__file__))

import pytest


@pytest.fixture
def repo_root():
    """Absolute path to the repository root."""
    return os.path.dirname(os.path.abspath(__file__))


@pytest.fixture
def samples_dir(repo_root):
    """Absolute path to the samples/ directory."""
    return os.path.join(repo_root, "samples")
