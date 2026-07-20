"""Live scoring-progress state (percent + current stage) for the result page.

grade_submission writes the latest ``{phase, done, total, pct, label}`` snapshot to
``data/scoring_progress/{submission_id}.json`` after each check; the web status
endpoint reads it so the participant sees how far the grading got. Best-effort — a
write/read failure never affects the score."""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

_DEFAULT_TMPL = "data/scoring_progress/{submission_id}.json"


def _path(config: Any, submission_id: str) -> str:
    tmpl = (config.get("scoring.progress_dir", _DEFAULT_TMPL) if config else _DEFAULT_TMPL)
    rel = str(tmpl).format(submission_id=submission_id)
    if os.path.isabs(rel):
        return rel
    # ``__file__`` is scoring/engine/progress.py — the data dir lives at the repo
    # root, two levels up.
    repo_root = os.path.join(os.path.dirname(__file__), "..", "..")
    return os.path.normpath(os.path.join(repo_root, rel))


def write(config: Any, submission_id: str, *, phase: str, done: int, total: int, label: str) -> None:
    total = max(int(total), 1)
    pct = int(round(100.0 * min(done, total) / total))
    payload = {"phase": phase, "done": int(done), "total": total, "pct": pct,
               "label": str(label), "at": time.time()}
    try:
        p = _path(config, submission_id)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except OSError:
        pass  # progress is cosmetic — never break grading


def read(config: Any, submission_id: str) -> Optional[Dict[str, Any]]:
    try:
        with open(_path(config, submission_id), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def clear(config: Any, submission_id: str) -> None:
    try:
        os.remove(_path(config, submission_id))
    except OSError:
        pass
