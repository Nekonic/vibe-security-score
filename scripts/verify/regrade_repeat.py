"""Re-grade the same generated apps N times and log every verdict (no DB writes).

    PYTHONPATH=. uv run python scripts/verify/regrade_repeat.py 6,8,10,14 5 out.jsonl

Each line: sub, run, final, raw, crit, checks{check_id: [score, passed, skipped, reasons]}.
Compare runs per check to prove grading is repeatable.
"""
import json
import sys
import time
import traceback

from scoring import grade_submission

ids, runs, out = [int(x) for x in sys.argv[1].split(",")], int(sys.argv[2]), sys.argv[3]
for n in range(1, runs + 1):
    for sid in ids:
        t = time.time()
        rec = {"sub": sid, "run": n}
        try:
            r = grade_submission(f"rep-{sid}-{n}", f"data/generated/{sid}")
            rec.update(final=r.get("final_score"), raw=r.get("raw_score"),
                       crit=[c.get("check_id") for c in r.get("critical_penalties", [])],
                       checks={f["check_id"]: [f["score"], f["passed"], f.get("skipped", False),
                                               f.get("penalty_reasons", [])] for f in r["findings"]})
        except Exception as e:
            rec["error"] = repr(e)
            rec["tb"] = traceback.format_exc()[-1500:]
        rec["secs"] = round(time.time() - t, 1)
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        print(sid, n, rec.get("final"), rec.get("error", ""), rec["secs"], flush=True)
