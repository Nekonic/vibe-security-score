"""Config loader — reads config/scoring.yaml, the single source of tunables."""
from __future__ import annotations

import copy
import os
import threading
from typing import Any, Dict, Tuple

import yaml

_DEFAULT_CONFIG_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "config", "scoring.yaml")
)


class Config:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        # Dev mode: skip external security CLIs and use built-in/offline checks.
        # Default False => require and run the configured external tools;
        # enable dev mode with the CLI `--dev` flag or grade_submission(dev=True).
        self.dev = bool(raw.get("dev", False))
        self.category_weights = self._normalize_category_weights(
            raw.get("categories", {})
        )

    @staticmethod
    def _normalize_category_weights(categories: Dict[str, Any]) -> Dict[str, float]:
        raw_weights = {
            name: float(spec.get("weight", 0.0))
            for name, spec in categories.items()
        }
        total = sum(raw_weights.values())
        if total <= 0:
            n = len(raw_weights) or 1
            return {k: 1.0 / n for k in raw_weights}
        return {k: v / total for k, v in raw_weights.items()}

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    @property
    def category_labels(self) -> Dict[str, str]:
        """category id -> human label for reporting/UI."""
        cats = self.raw.get("categories", {}) or {}
        return {name: str(spec.get("label", name)) for name, spec in cats.items()}

    @property
    def category_map(self) -> Dict[str, str]:
        """check_id -> category id, built from categories[*].checks. Lets the
        operator re-bucket any check purely via config."""
        out: Dict[str, str] = {}
        for name, spec in (self.raw.get("categories", {}) or {}).items():
            for cid in (spec.get("checks", []) or []):
                out[str(cid)] = name
        return out

    @property
    def static_checks(self) -> Dict[str, Any]:
        return self.get("static.checks", {}) or {}

    @property
    def static_dependencies(self) -> Dict[str, Any]:
        return self.get("static.dependencies", {}) or {}


# Parsed YAML per file, keyed on (mtime_ns, size): the preview proxy and the
# result pages load the config per request and the parse alone costs ~100 ms.
_CACHE: Dict[str, Tuple[Tuple[int, int], Dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()


def load_config(path: str = _DEFAULT_CONFIG_PATH) -> Config:
    """A fresh ``Config`` for ``path``. The YAML is parsed once per file version;
    each call gets its own deep copy, since callers mutate the result
    (``cfg.dev = True``, ``cfg.raw["codex"][...] = ...``)."""
    key = os.path.abspath(path)
    st = os.stat(key)
    stamp = (st.st_mtime_ns, st.st_size)
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
    if hit is None or hit[0] != stamp:
        with open(key, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        with _CACHE_LOCK:
            _CACHE[key] = (stamp, raw)
    else:
        raw = hit[1]
    return Config(copy.deepcopy(raw))
