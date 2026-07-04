"""Config loader — reads config/scoring.yaml, the single source of tunables."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

import yaml

_DEFAULT_CONFIG_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "config", "scoring.yaml")
)


class Config:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self._grades = self._parse_grades(raw.get("grades", []))
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

    @staticmethod
    def _parse_grades(grades: List[Dict[str, Any]]) -> List[Tuple[float, str]]:
        parsed = [(float(g["min"]), str(g["name"])) for g in grades]
        parsed.sort(key=lambda t: t[0], reverse=True)
        return parsed

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.raw
        for part in dotted.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return default
        return node

    def grade_for(self, score: float) -> str:
        for minimum, name in self._grades:  # sorted desc
            if score >= minimum:
                return name
        return self._grades[-1][1] if self._grades else ""

    @property
    def static_checks(self) -> Dict[str, Any]:
        return self.get("static.checks", {}) or {}

    @property
    def static_dependencies(self) -> Dict[str, Any]:
        return self.get("static.dependencies", {}) or {}


def load_config(path: str = _DEFAULT_CONFIG_PATH) -> Config:
    with open(path, "r", encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    return Config(raw or {})
