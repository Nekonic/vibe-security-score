"""Re-aggregate stored findings under an edited copy of config/scoring.yaml — no regrade.
Use it to see how a weighting or critical-penalty change moves every graded app.

    PYTHONPATH=. uv run python scripts/verify/sim_scores.py path/to/edited-scoring.yaml
"""
import json
import sqlite3
import sys

import yaml

from scoring.config import Config, load_config
from scoring.engine import efficiency
from scoring.engine.aggregate import combine_scores
from scoring.models import CheckResult

FIELDS = {"unproven", "check_id", "category", "label", "score", "weight", "passed", "penalty_reasons",
          "evidence", "skipped", "tool"}


def scores(cfg: Config):
    con = sqlite3.connect("grader/db.sqlite3")
    rows = con.execute("select id, participant, findings, prompt_chars from submissions_submission "
                       "where status='done' order by id").fetchall()
    for sid, part, findings, chars in rows:
        found = json.loads(findings)
        boot = any("부팅 실패" in " ".join(f.get("penalty_reasons", [])) for f in found)
        func = next((f for f in found if f["check_id"] == "functional"), {})
        checks = [CheckResult(**{k: v for k, v in f.items() if k in FIELDS}) for f in found]
        g = combine_scores(checks, cfg, functional_failed=not func.get("passed", True) and not func.get("skipped"),
                           boot_failed=boot)
        final = efficiency.apply({"final_score": g.score, "boot_failed": boot}, int(chars or 0), cfg)["final_score"]
        yield sid, part, g.raw_score, final, [p.check_id for p in g.critical_penalties]


current = {sid: final for sid, _p, _r, final, _c in scores(load_config())}
edited = Config(yaml.safe_load(open(sys.argv[1], encoding="utf-8")))
for sid, part, raw, final, crit in scores(edited):
    print(f"#{sid:<3} {part[:16]:16} raw {raw:6.2f}  final {current[sid]:6.2f} -> {final:6.2f}  critical {crit}")
