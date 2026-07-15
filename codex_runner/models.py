"""Discover the Codex model catalog from the CLI itself (`codex debug models`) so
the operator PICKS a real, currently-supported model AND reasoning effort instead
of typing a guessed value (a wrong slug/level makes every generation fail). Source
of truth = the installed CLI, never a hardcoded/internet list."""
from __future__ import annotations

import json
import subprocess
import time
from typing import Any, Dict, List, Optional

from scoring.config import Config, load_config

from .runner import _binary_argv, _scrubbed_env

# The single settings page is opened rarely; a short cache avoids re-spawning the
# CLI on every admin render without pinning a stale catalog for long.
_TTL_SECONDS = 120.0
_cache: Dict[str, Any] = {"at": 0.0, "catalog": None}


def _catalog(config: Optional[Config] = None, *, force: bool = False) -> List[Dict[str, Any]]:
    """Cached list of user-selectable (visibility == "list") model dicts, each with
    ``slug``, ``display_name`` and ordered ``efforts``/``effort_desc`` from the CLI.
    Empty on any CLI failure — callers degrade gracefully, never block."""
    now = time.monotonic()
    if not force and _cache["catalog"] is not None and now - _cache["at"] < _TTL_SECONDS:
        return _cache["catalog"]
    cat = _query(config)
    _cache.update(at=now, catalog=cat)
    return cat


def _query(config: Optional[Config]) -> List[Dict[str, Any]]:
    if config is None:
        config = load_config()
    argv = _binary_argv(config) + ["debug", "models"]
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            env=_scrubbed_env(config), timeout=30, check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return []
    if proc.returncode != 0 or not proc.stdout:
        return []
    try:
        data = json.loads(proc.stdout)
    except (ValueError, TypeError):
        return []

    out: List[Dict[str, Any]] = []
    for m in (data.get("models", []) if isinstance(data, dict) else []):
        if not isinstance(m, dict) or m.get("visibility") != "list":
            continue
        slug = str(m.get("slug") or "").strip()
        if not slug:
            continue
        levels = m.get("supported_reasoning_levels") or []
        efforts = [str(l.get("effort")) for l in levels if isinstance(l, dict) and l.get("effort")]
        effort_desc = {
            str(l["effort"]): str(l.get("description") or "")
            for l in levels if isinstance(l, dict) and l.get("effort")
        }
        out.append({
            "slug": slug,
            "display_name": str(m.get("display_name") or slug),
            "efforts": efforts,                      # CLI order (low..xhigh..)
            "effort_desc": effort_desc,
            "_priority": m.get("priority") or 0,
        })
    out.sort(key=lambda x: -x["_priority"])
    return out


def available_models(config: Optional[Config] = None, *, force: bool = False) -> List[Dict[str, str]]:
    """[{"slug", "display_name"}] for selectable models, highest priority first."""
    return [{"slug": m["slug"], "display_name": m["display_name"]} for m in _catalog(config, force=force)]


def available_reasoning_efforts(config: Optional[Config] = None, *, force: bool = False) -> List[Dict[str, str]]:
    """[{"effort", "description"}] for reasoning levels supported by EVERY selectable
    model (intersection), in the CLI's own order — so any model+effort pairing is
    valid regardless of which model is picked. Empty if the catalog can't be read."""
    cat = _catalog(config, force=force)
    if not cat:
        return []
    common = set(cat[0]["efforts"])
    for m in cat[1:]:
        common &= set(m["efforts"])
    ordered = [e for e in cat[0]["efforts"] if e in common]  # preserve CLI order
    desc: Dict[str, str] = {}
    for m in cat:
        for e, d in m["effort_desc"].items():
            if e in common:
                desc.setdefault(e, d)
    return [{"effort": e, "description": desc.get(e, "")} for e in ordered]
