import sqlite3
c = sqlite3.connect("backend/phantompatch.db")
tables = [r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
print("tables:", tables)
for t in tables:
    n = c.execute(f"SELECT COUNT(*) FROM [{t}]").fetchone()[0]
    print(f"{t}: {n}")
# sample survey if any
if "survey_responses" in tables:
    rows = c.execute("SELECT rater_id, cve_id, item_id FROM survey_responses LIMIT 5").fetchall()
    print("survey sample:", rows)
