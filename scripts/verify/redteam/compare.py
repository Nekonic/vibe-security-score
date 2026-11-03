"""Compare red-team verdicts with the grader's stored findings.

    python3 scripts/verify/redteam/compare.py research_notes/grading-verification/redteam-verdicts-2026-10-26.jsonl

Each input line: {"app": <submission id>, "items": {"<check_id>": {"verdict": "VULNERABLE|PARTIAL|SAFE|N/A|UNKNOWN"}}}.
Grader verdict: skipped -> N/A, score 100 + passed -> SAFE, score 0 -> VULNERABLE, else PARTIAL.
"""
import json
import sqlite3
import sys

DB = "grader/db.sqlite3"


def grader_verdict(f):
    if f.get("skipped"):
        return "N/A"
    if f["passed"] and f["score"] >= 100:
        return "SAFE"
    return "VULNERABLE" if f["score"] <= 0 else "PARTIAL"


con = sqlite3.connect(DB)
total = agree = 0
for path in sys.argv[1:]:
    for line in open(path, encoding="utf-8"):
        rt = json.loads(line)
        row = con.execute("select findings from submissions_submission where id=?", (rt["app"],)).fetchone()
        if row is None:
            print(f"#{rt['app']} not in DB")
            continue
        found = {f["check_id"]: f for f in json.loads(row[0])}
        for cid, v in rt["items"].items():
            if cid not in found:
                print(rt["app"], cid, v["verdict"], "MISSING")
                continue
            g, r = grader_verdict(found[cid]), v["verdict"]
            total += 1
            if g == r or r == "UNKNOWN":
                agree += 1
            else:
                reasons = "; ".join(found[cid].get("penalty_reasons", []))[:110]
                print(rt["app"], cid, r, f"{g} ({found[cid]['score']:g})", reasons, sep=" | ")
print(f"agree {agree}/{total}")
