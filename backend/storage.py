"""
storage.py — SQLite persistence layer using aiosqlite.
Upserts on cve_id so re-runs never create duplicates.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("PHANTOMPATCH_DB", "phantompatch.db")

CREATE_CVES = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id              TEXT PRIMARY KEY,
    description         TEXT,
    cvss_base_score     REAL,
    cvss_vector         TEXT,
    severity            TEXT,
    cwe_ids             TEXT,
    published_date      TEXT,
    last_modified_date  TEXT,
    affected_cpes       TEXT,
    vendors             TEXT,
    reference_urls      TEXT,
    epss_score          REAL DEFAULT 0.0,
    in_kev              INTEGER DEFAULT 0,
    priority_score      REAL DEFAULT 0.0,
    priority_label      TEXT DEFAULT 'LOW',
    reasons             TEXT DEFAULT '[]',
    ingested_at         TEXT
)
"""

CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type  TEXT,
    cve_id      TEXT,
    detail      TEXT,
    created_at  TEXT
)
"""

CREATE_RUNS = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    start_date    TEXT,
    end_date      TEXT,
    status        TEXT,
    cves_fetched  INTEGER DEFAULT 0,
    started_at    TEXT,
    finished_at   TEXT
)
"""


async def init_db() -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(CREATE_CVES)
        await db.execute(CREATE_EVENTS)
        await db.execute(CREATE_RUNS)
        await db.commit()
    logger.info("Database initialised at %s", DB_PATH)


async def upsert_cve(record: dict[str, Any]) -> bool:
    """
    Insert or update a CVE record.
    Returns True if this was a new insert, False if an update.
    """
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        existing = await db.execute(
            "SELECT priority_label FROM cves WHERE cve_id = ?", (record["cve_id"],)
        )
        row = await existing.fetchone()
        is_new = row is None

        await db.execute(
            """
            INSERT INTO cves (
                cve_id, description, cvss_base_score, cvss_vector, severity,
                cwe_ids, published_date, last_modified_date, affected_cpes, vendors,
                reference_urls, epss_score, in_kev, priority_score,
                priority_label, reasons, ingested_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                cvss_base_score=excluded.cvss_base_score,
                cvss_vector=excluded.cvss_vector,
                severity=excluded.severity,
                cwe_ids=excluded.cwe_ids,
                last_modified_date=excluded.last_modified_date,
                affected_cpes=excluded.affected_cpes,
                vendors=excluded.vendors,
                reference_urls=excluded.reference_urls,
                epss_score=excluded.epss_score,
                in_kev=excluded.in_kev,
                priority_score=excluded.priority_score,
                priority_label=excluded.priority_label,
                reasons=excluded.reasons,
                ingested_at=excluded.ingested_at
            """,
            (
                record["cve_id"],
                record.get("description"),
                record.get("cvss_base_score"),
                record.get("cvss_vector"),
                record.get("severity"),
                record.get("cwe_ids", "[]"),
                record.get("published_date"),
                record.get("last_modified_date"),
                record.get("affected_cpes", "[]"),
                record.get("vendors", "[]"),
                record.get("reference_urls", "[]"),
                record.get("epss_score", 0.0),
                1 if record.get("in_kev") else 0,
                record.get("priority_score", 0.0),
                record.get("priority_label", "LOW"),
                json.dumps(record.get("reasons", [])),
                now,
            ),
        )
        await db.commit()

        # Log priority escalation event
        if not is_new and row and row["priority_label"] != record.get("priority_label"):
            await _log_event(
                db,
                "PRIORITY_CHANGE",
                record["cve_id"],
                f"Priority changed from {row['priority_label']} to {record.get('priority_label')}",
            )
        elif not is_new and record.get("in_kev"):
            await _log_event(db, "KEV_ADDED", record["cve_id"], "Added to CISA KEV catalog")
        elif is_new:
            await _log_event(db, "CVE_ADDED", record["cve_id"], f"New CVE ingested — {record.get('priority_label')}")

    return is_new


async def _log_event(db: aiosqlite.Connection, event_type: str, cve_id: str, detail: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT INTO events (event_type, cve_id, detail, created_at) VALUES (?,?,?,?)",
        (event_type, cve_id, detail, now),
    )
    await db.commit()


async def create_run(start_date: str, end_date: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO pipeline_runs (start_date, end_date, status, started_at) VALUES (?,?,?,?)",
            (start_date, end_date, "RUNNING", now),
        )
        await db.commit()
        return cur.lastrowid


async def finish_run(run_id: int, cves_fetched: int, status: str = "COMPLETE") -> None:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE pipeline_runs SET status=?, cves_fetched=?, finished_at=? WHERE id=?",
            (status, cves_fetched, now, run_id),
        )
        await db.commit()
