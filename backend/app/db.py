"""
db.py — SQLite persistence layer with all PhantomPatch tables.

Upsert-only design: re-runs never create duplicates.
Uses aiosqlite for async access.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import aiosqlite

from app.config import DB_PATH

logger = logging.getLogger(__name__)


# ── Table DDL ────────────────────────────────────────────────────────────────

CREATE_CVES = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id              TEXT PRIMARY KEY,
    description         TEXT,
    cvss_base_score     REAL,
    cvss_vector         TEXT,
    severity            TEXT,
    attack_vector       TEXT,
    cwe_ids             TEXT DEFAULT '[]',
    published_date      TEXT,
    last_modified_date  TEXT,
    affected_cpes       TEXT DEFAULT '[]',
    cpe_version_ranges  TEXT DEFAULT '[]',
    vendors             TEXT DEFAULT '[]',
    products            TEXT DEFAULT '[]',
    reference_urls      TEXT DEFAULT '[]',
    patch_references    TEXT DEFAULT '[]',
    reference_tags      TEXT DEFAULT '{}',
    epss_score          REAL DEFAULT 0.0,
    epss_percentile     REAL,
    in_kev              INTEGER DEFAULT 0,
    priority_score      REAL DEFAULT 0.0,
    priority_label      TEXT DEFAULT 'LOW',
    priority_breakdown  TEXT DEFAULT '{}',
    missing_signals     TEXT DEFAULT '[]',
    reasons             TEXT DEFAULT '[]',
    score_model         TEXT,
    score_version       TEXT,
    cvss_version        TEXT,
    ingested_at         TEXT
)
"""

CREATE_CWE = """
CREATE TABLE IF NOT EXISTS cwe (
    cwe_id       TEXT PRIMARY KEY,
    name         TEXT,
    description  TEXT,
    consequences TEXT DEFAULT '[]',
    mitigations  TEXT DEFAULT '[]',
    fetched_at   TEXT
)
"""

CREATE_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id       TEXT,
    audience     TEXT DEFAULT 'executive',
    content_json TEXT,
    data_hash    TEXT,
    pdf_blob     BLOB,
    created_at   TEXT
)
"""


CREATE_KEV = """
CREATE TABLE IF NOT EXISTS kev (
    cve_id              TEXT PRIMARY KEY,
    vendor_project      TEXT,
    product             TEXT,
    vulnerability_name  TEXT,
    date_added          TEXT,
    due_date            TEXT,
    required_action     TEXT,
    known_ransomware_use TEXT,
    short_description   TEXT
)
"""

CREATE_EPSS = """
CREATE TABLE IF NOT EXISTS epss (
    cve_id      TEXT PRIMARY KEY,
    probability REAL,
    percentile  REAL,
    fetched_at  TEXT
)
"""

CREATE_NARRATIVES = """
CREATE TABLE IF NOT EXISTS narratives (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id          TEXT NOT NULL,
    audience        TEXT NOT NULL,
    narrative_text  TEXT NOT NULL,
    prompt_version  TEXT DEFAULT 'v1',
    provider        TEXT DEFAULT 'mock',
    model           TEXT DEFAULT '',
    verification    TEXT DEFAULT '{}',
    confidence      TEXT DEFAULT 'LOW',
    faithfulness_score REAL DEFAULT 0.0,
    attempt_count   INTEGER DEFAULT 1,
    created_at      TEXT,
    UNIQUE(cve_id, audience)
)
"""

CREATE_EVAL_RUNS = """
CREATE TABLE IF NOT EXISTS eval_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    eval_type   TEXT NOT NULL,
    provider    TEXT,
    model       TEXT,
    results     TEXT DEFAULT '{}',
    created_at  TEXT
)
"""

CREATE_SURVEY_RESPONSES = """
CREATE TABLE IF NOT EXISTS survey_responses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id         TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    condition       TEXT NOT NULL,
    rater_id        TEXT NOT NULL,
    clarity_rating  INTEGER NOT NULL,
    would_act       INTEGER,
    created_at      TEXT
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

CREATE_PIPELINE_RUNS = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    start_date    TEXT,
    end_date      TEXT,
    status        TEXT,
    cves_fetched  INTEGER DEFAULT 0,
    parse_failures INTEGER DEFAULT 0,
    parse_rate    REAL DEFAULT 0.0,
    started_at    TEXT,
    finished_at   TEXT
)
"""

CREATE_SYNC_STATE = """
CREATE TABLE IF NOT EXISTS sync_state (
    source              TEXT PRIMARY KEY,
    last_success_at     TEXT,
    last_cursor         TEXT,
    last_error          TEXT,
    consecutive_failures INTEGER DEFAULT 0
)
"""

ALL_TABLES = [
    CREATE_CVES, CREATE_KEV, CREATE_EPSS, CREATE_NARRATIVES,
    CREATE_EVAL_RUNS, CREATE_SURVEY_RESPONSES, CREATE_EVENTS,
    CREATE_PIPELINE_RUNS, CREATE_SYNC_STATE, CREATE_CWE, CREATE_REPORTS,
]


# ── Init ─────────────────────────────────────────────────────────────────────

async def init_db() -> None:
    """Create all tables if they don't exist and run auto-migrations for missing columns."""
    async with aiosqlite.connect(DB_PATH) as db:
        for ddl in ALL_TABLES:
            await db.execute(ddl)

        # Check and migrate cves table columns if an older database file exists
        cur = await db.execute("PRAGMA table_info(cves)")
        existing_cve_cols = {row[1] for row in await cur.fetchall()}

        cve_columns_to_add = {
            "attack_vector": "TEXT",
            "cwe_ids": "TEXT DEFAULT '[]'",
            "vendors": "TEXT DEFAULT '[]'",
            "products": "TEXT DEFAULT '[]'",
            "patch_references": "TEXT DEFAULT '[]'",
            "cpe_version_ranges": "TEXT DEFAULT '[]'",
            "reference_tags": "TEXT DEFAULT '{}'",
            "epss_percentile": "REAL",
            "priority_breakdown": "TEXT DEFAULT '{}'",
            "missing_signals": "TEXT DEFAULT '[]'",
            "reasons": "TEXT DEFAULT '[]'",
            "score_model": "TEXT",
            "score_version": "TEXT",
            "cvss_version": "TEXT",
        }
        for col_name, col_type in cve_columns_to_add.items():
            if col_name not in existing_cve_cols:
                logger.info("Migrating database: adding missing column '%s' to cves table", col_name)
                await db.execute(f"ALTER TABLE cves ADD COLUMN {col_name} {col_type}")

        # Check and migrate pipeline_runs table columns
        cur = await db.execute("PRAGMA table_info(pipeline_runs)")
        existing_run_cols = {row[1] for row in await cur.fetchall()}

        run_columns_to_add = {
            "parse_failures": "INTEGER DEFAULT 0",
            "parse_rate": "REAL DEFAULT 0.0",
        }
        for col_name, col_type in run_columns_to_add.items():
            if col_name not in existing_run_cols:
                logger.info("Migrating database: adding missing column '%s' to pipeline_runs table", col_name)
                await db.execute(f"ALTER TABLE pipeline_runs ADD COLUMN {col_name} {col_type}")

        # Check and migrate reports table columns
        cur = await db.execute("PRAGMA table_info(reports)")
        existing_report_cols = {row[1] for row in await cur.fetchall()}
        if "pdf_blob" not in existing_report_cols:
            logger.info("Migrating database: adding missing column 'pdf_blob' to reports table")
            await db.execute("ALTER TABLE reports ADD COLUMN pdf_blob BLOB")

        await db.commit()
    logger.info("Database initialised at %s", DB_PATH)


# ── Generic helpers ──────────────────────────────────────────────────────────

async def query(sql: str, params: tuple = ()) -> list[dict]:
    """Execute a SELECT and return list of dicts."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute(sql, params)
        rows = await cur.fetchall()
        return [dict(r) for r in rows]


async def scalar(sql: str, params: tuple = (), default: Any = 0) -> Any:
    """Execute a SELECT and return the first column of the first row."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(sql, params)
        row = await cur.fetchone()
        return row[0] if row and row[0] is not None else default


async def execute(sql: str, params: tuple = ()) -> int:
    """Execute an INSERT/UPDATE/DELETE and return lastrowid."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(sql, params)
        await db.commit()
        return cur.lastrowid or 0


# ── CVE operations ───────────────────────────────────────────────────────────

async def upsert_cve(record: dict[str, Any]) -> bool:
    """Insert or update a CVE record. Returns True if new insert."""
    now = datetime.now(timezone.utc).isoformat()

    def json_value(field: str, default: str) -> str:
        value = record.get(field)
        if value is None:
            return default
        if isinstance(value, (list, dict)):
            return json.dumps(value)
        return value

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
                attack_vector, cwe_ids, published_date, last_modified_date,
                affected_cpes, cpe_version_ranges, vendors, products, reference_urls, patch_references,
                reference_tags, epss_score, epss_percentile, in_kev, priority_score,
                priority_label, priority_breakdown, missing_signals, reasons,
                score_model, score_version, cvss_version, ingested_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                description=excluded.description,
                cvss_base_score=excluded.cvss_base_score,
                cvss_vector=excluded.cvss_vector,
                severity=excluded.severity,
                attack_vector=excluded.attack_vector,
                cwe_ids=excluded.cwe_ids,
                last_modified_date=excluded.last_modified_date,
                affected_cpes=excluded.affected_cpes,
                cpe_version_ranges=excluded.cpe_version_ranges,
                vendors=excluded.vendors,
                products=excluded.products,
                reference_urls=excluded.reference_urls,
                patch_references=excluded.patch_references,
                reference_tags=excluded.reference_tags,
                epss_score=excluded.epss_score,
                epss_percentile=excluded.epss_percentile,
                in_kev=excluded.in_kev,
                priority_score=excluded.priority_score,
                priority_label=excluded.priority_label,
                priority_breakdown=excluded.priority_breakdown,
                missing_signals=excluded.missing_signals,
                reasons=excluded.reasons,
                score_model=excluded.score_model,
                score_version=excluded.score_version,
                cvss_version=excluded.cvss_version,
                ingested_at=excluded.ingested_at
            """,
            (
                record["cve_id"],
                record.get("description"),
                record.get("cvss_base_score"),
                record.get("cvss_vector"),
                record.get("severity"),
                record.get("attack_vector"),
                json_value("cwe_ids", "[]"),
                record.get("published_date"),
                record.get("last_modified_date"),
                json_value("affected_cpes", "[]"),
                json_value("cpe_version_ranges", "[]"),
                json_value("vendors", "[]"),
                json_value("products", "[]"),
                json_value("reference_urls", "[]"),
                json_value("patch_references", "[]"),
                json_value("reference_tags", "{}"),
                record.get("epss_score", 0.0),
                record.get("epss_percentile"),
                1 if record.get("in_kev") else 0,
                record.get("priority_score", 0.0),
                record.get("priority_label", "LOW"),
                json_value("priority_breakdown", "{}"),
                json_value("missing_signals", "[]"),
                json_value("reasons", "[]"),
                record.get("score_model"),
                record.get("score_version"),
                record.get("cvss_version"),
                now,
            ),
        )

        # Log events
        if is_new:
            await _log_event(db, "CVE_ADDED", record["cve_id"],
                             f"New CVE ingested — {record.get('priority_label')}")
        elif row and row["priority_label"] != record.get("priority_label"):
            await _log_event(db, "PRIORITY_CHANGE", record["cve_id"],
                             f"Priority: {row['priority_label']} -> {record.get('priority_label')}")

        await db.commit()
    return is_new


async def get_cve(cve_id: str) -> Optional[dict]:
    """Get a single CVE record."""
    rows = await query("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
    if not rows:
        return None
    row = rows[0]
    _deserialize_json_fields(row)
    return row


async def get_cves(
    priority: Optional[str] = None,
    in_kev: Optional[bool] = None,
    min_epss: Optional[float] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "priority_score",
    sort_dir: str = "DESC",
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Get filtered, sorted, paginated CVE list."""
    conditions: list[str] = []
    params: list[Any] = []

    if priority:
        conditions.append("priority_label = ?")
        params.append(priority.upper())
    if in_kev is not None:
        conditions.append("in_kev = ?")
        params.append(1 if in_kev else 0)
    if min_epss is not None:
        conditions.append("epss_score >= ?")
        params.append(min_epss)
    if severity:
        conditions.append("severity = ?")
        params.append(severity.upper())
    if search:
        search_pattern = f"%{search}%"
        conditions.append("(cve_id LIKE ? OR description LIKE ? OR vendors LIKE ? OR products LIKE ?)")
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

    # Validate sort column
    allowed_sorts = {"priority_score", "cvss_base_score", "epss_score", "published_date", "cve_id"}
    if sort_by not in allowed_sorts:
        sort_by = "priority_score"
    sort_dir = "ASC" if sort_dir.upper() == "ASC" else "DESC"

    rows = await query(
        f"SELECT * FROM cves {where} ORDER BY {sort_by} {sort_dir} LIMIT ? OFFSET ?",
        tuple(params + [limit, offset]),
    )
    total = await scalar(f"SELECT COUNT(*) FROM cves {where}", tuple(params))

    for r in rows:
        _deserialize_json_fields(r)
    return rows, total


def _deserialize_json_fields(row: dict) -> None:
    """In-place deserialize JSON string fields."""
    for field in ("cwe_ids", "affected_cpes", "cpe_version_ranges", "vendors", "products",
                  "reference_urls", "patch_references", "reasons",
                  "missing_signals"):
        try:
            val = row.get(field)
            if isinstance(val, str):
                row[field] = json.loads(val)
        except (json.JSONDecodeError, TypeError):
            row[field] = []
    # Deserialize priority_breakdown and reference_tags
    try:
        bd = row.get("priority_breakdown")
        if isinstance(bd, str):
            row["priority_breakdown"] = json.loads(bd)
    except (json.JSONDecodeError, TypeError):
        row["priority_breakdown"] = {}

    try:
        rt = row.get("reference_tags")
        if isinstance(rt, str):
            row["reference_tags"] = json.loads(rt)
        elif rt is None:
            row["reference_tags"] = {}
    except (json.JSONDecodeError, TypeError):
        row["reference_tags"] = {}


# ── KEV operations ───────────────────────────────────────────────────────────

async def upsert_kev(record: dict[str, Any]) -> None:
    """Insert or update a KEV entry."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name,
                            date_added, due_date, required_action, known_ransomware_use,
                            short_description)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                vendor_project=excluded.vendor_project,
                product=excluded.product,
                vulnerability_name=excluded.vulnerability_name,
                date_added=excluded.date_added,
                due_date=excluded.due_date,
                required_action=excluded.required_action,
                known_ransomware_use=excluded.known_ransomware_use,
                short_description=excluded.short_description
            """,
            (
                record["cve_id"],
                record.get("vendor_project"),
                record.get("product"),
                record.get("vulnerability_name"),
                record.get("date_added"),
                record.get("due_date"),
                record.get("required_action"),
                record.get("known_ransomware_use"),
                record.get("short_description"),
            ),
        )
        await db.commit()


async def get_kev(cve_id: str) -> Optional[dict]:
    """Get KEV details for a CVE."""
    rows = await query("SELECT * FROM kev WHERE cve_id = ?", (cve_id,))
    return rows[0] if rows else None


async def get_all_kev_ids() -> set[str]:
    """Get all CVE IDs in the KEV table."""
    rows = await query("SELECT cve_id FROM kev")
    return {r["cve_id"] for r in rows}


# ── EPSS operations ──────────────────────────────────────────────────────────

async def upsert_epss(cve_id: str, probability: float, percentile: float) -> None:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO epss (cve_id, probability, percentile, fetched_at)
            VALUES (?,?,?,?)
            ON CONFLICT(cve_id) DO UPDATE SET
                probability=excluded.probability,
                percentile=excluded.percentile,
                fetched_at=excluded.fetched_at
            """,
            (cve_id, probability, percentile, now),
        )
        await db.commit()


async def get_epss(cve_id: str) -> Optional[dict]:
    rows = await query("SELECT * FROM epss WHERE cve_id = ?", (cve_id,))
    return rows[0] if rows else None


# ── Narrative operations ─────────────────────────────────────────────────────

async def upsert_narrative(record: dict[str, Any]) -> int:
    """Insert or update a narrative. Returns the row id."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO narratives (
                cve_id, audience, narrative_text, prompt_version, provider, model,
                verification, confidence, faithfulness_score, attempt_count, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(cve_id, audience) DO UPDATE SET
                narrative_text=excluded.narrative_text,
                prompt_version=excluded.prompt_version,
                provider=excluded.provider,
                model=excluded.model,
                verification=excluded.verification,
                confidence=excluded.confidence,
                faithfulness_score=excluded.faithfulness_score,
                attempt_count=excluded.attempt_count,
                created_at=excluded.created_at
            """,
            (
                record["cve_id"],
                record["audience"],
                record["narrative_text"],
                record.get("prompt_version", "v1"),
                record.get("provider", "mock"),
                record.get("model", ""),
                json.dumps(record.get("verification", {})),
                record.get("confidence", "LOW"),
                record.get("faithfulness_score", 0.0),
                record.get("attempt_count", 1),
                now,
            ),
        )
        await db.commit()
        return cur.lastrowid or 0


async def get_narratives(cve_id: str) -> list[dict]:
    """Get all narratives for a CVE."""
    rows = await query(
        "SELECT * FROM narratives WHERE cve_id = ? ORDER BY audience", (cve_id,)
    )
    for r in rows:
        try:
            r["verification"] = json.loads(r.get("verification", "{}") or "{}")
        except (json.JSONDecodeError, TypeError):
            r["verification"] = {}
    return rows


async def get_narrative(cve_id: str, audience: str) -> Optional[dict]:
    """Get a specific narrative."""
    rows = await query(
        "SELECT * FROM narratives WHERE cve_id = ? AND audience = ?",
        (cve_id, audience),
    )
    if not rows:
        return None
    r = rows[0]
    try:
        r["verification"] = json.loads(r.get("verification", "{}") or "{}")
    except (json.JSONDecodeError, TypeError):
        r["verification"] = {}
    return r


# ── Survey operations ────────────────────────────────────────────────────────

async def insert_survey_response(record: dict[str, Any]) -> int:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            INSERT INTO survey_responses (item_id, cve_id, condition, rater_id,
                                          clarity_rating, would_act, created_at)
            VALUES (?,?,?,?,?,?,?)
            """,
            (
                record["item_id"],
                record["cve_id"],
                record["condition"],
                record["rater_id"],
                record["clarity_rating"],
                1 if record.get("would_act") else (0 if record.get("would_act") is False else None),
                now,
            ),
        )
        await db.commit()
        return cur.lastrowid or 0


async def get_survey_responses() -> list[dict]:
    return await query("SELECT * FROM survey_responses ORDER BY created_at")


# ── Eval runs ────────────────────────────────────────────────────────────────

async def insert_eval_run(eval_type: str, provider: str, model: str, results: dict) -> int:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO eval_runs (eval_type, provider, model, results, created_at) VALUES (?,?,?,?,?)",
            (eval_type, provider, model, json.dumps(results), now),
        )
        await db.commit()
        return cur.lastrowid or 0


async def get_latest_eval(eval_type: str) -> Optional[dict]:
    rows = await query(
        "SELECT * FROM eval_runs WHERE eval_type = ? ORDER BY id DESC LIMIT 1",
        (eval_type,),
    )
    if not rows:
        return None
    r = rows[0]
    try:
        r["results"] = json.loads(r.get("results", "{}") or "{}")
    except (json.JSONDecodeError, TypeError):
        r["results"] = {}
    return r


# ── Pipeline runs ────────────────────────────────────────────────────────────

async def create_run(start_date: str, end_date: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO pipeline_runs (start_date, end_date, status, started_at) VALUES (?,?,?,?)",
            (start_date, end_date, "RUNNING", now),
        )
        await db.commit()
        return cur.lastrowid or 0


async def finish_run(run_id: int, cves_fetched: int, status: str = "COMPLETE",
                     parse_failures: int = 0, parse_rate: float = 0.0) -> None:
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """UPDATE pipeline_runs SET status=?, cves_fetched=?, parse_failures=?,
               parse_rate=?, finished_at=? WHERE id=?""",
            (status, cves_fetched, parse_failures, parse_rate, now, run_id),
        )
        await db.commit()


async def _log_event(db: aiosqlite.Connection, event_type: str,
                     cve_id: str, detail: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        "INSERT INTO events (event_type, cve_id, detail, created_at) VALUES (?,?,?,?)",
        (event_type, cve_id, detail, now),
    )


async def log_event(event_type: str, cve_id: str, detail: str) -> int:
    """Public helper: insert an event and return its rowid."""
    now = datetime.now(timezone.utc).isoformat()
    return await execute(
        "INSERT INTO events (event_type, cve_id, detail, created_at) VALUES (?,?,?,?)",
        (event_type, cve_id, detail, now),
    )


async def get_recent_events(since_id: int = 0, limit: int = 100) -> list[dict]:
    """Return recent events with id > since_id, newest first."""
    rows = await query(
        "SELECT * FROM events WHERE id > ? ORDER BY id DESC LIMIT ?",
        (since_id, limit),
    )
    return rows


# ── Sync state ───────────────────────────────────────────────────────────────

async def get_sync_state(source: str) -> Optional[dict]:
    """Return the sync_state row for a source, or None if not present."""
    rows = await query("SELECT * FROM sync_state WHERE source = ?", (source,))
    return rows[0] if rows else None


async def get_all_sync_states() -> list[dict]:
    """Return all sync_state rows."""
    return await query("SELECT * FROM sync_state ORDER BY source")


async def upsert_sync_state(
    source: str,
    *,
    last_success_at: Optional[str] = None,
    last_cursor: Optional[str] = None,
    last_error: Optional[str] = None,
    consecutive_failures: Optional[int] = None,
) -> None:
    """Upsert a sync_state record, leaving unspecified fields unchanged."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cur = await db.execute("SELECT * FROM sync_state WHERE source = ?", (source,))
        existing = await cur.fetchone()

        if existing is None:
            await db.execute(
                """INSERT INTO sync_state
                   (source, last_success_at, last_cursor, last_error, consecutive_failures)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    source,
                    last_success_at,
                    last_cursor,
                    last_error,
                    consecutive_failures if consecutive_failures is not None else 0,
                ),
            )
        else:
            fields = []
            vals: list[Any] = []
            if last_success_at is not None:
                fields.append("last_success_at=?")
                vals.append(last_success_at)
            if last_cursor is not None:
                fields.append("last_cursor=?")
                vals.append(last_cursor)
            if last_error is not None:
                fields.append("last_error=?")
                vals.append(last_error)
            if consecutive_failures is not None:
                fields.append("consecutive_failures=?")
                vals.append(consecutive_failures)
            if fields:
                vals.append(source)
                await db.execute(
                    f"UPDATE sync_state SET {', '.join(fields)} WHERE source = ?", vals
                )
        await db.commit()


# ── Stats ────────────────────────────────────────────────────────────────────

async def get_cve_count() -> int:
    return await scalar("SELECT COUNT(*) FROM cves")


async def has_data() -> bool:
    return (await get_cve_count()) > 0


# ── CWE operations ───────────────────────────────────────────────────────────

async def get_cwe(cwe_id: str) -> Optional[dict]:
    """Retrieve a cached CWE definition."""
    rows = await query("SELECT * FROM cwe WHERE cwe_id = ?", (cwe_id,))
    if not rows:
        return None
    r = rows[0]
    for k in ("consequences", "mitigations"):
        if isinstance(r.get(k), str):
            try:
                r[k] = json.loads(r[k])
            except (json.JSONDecodeError, TypeError):
                r[k] = []
    return r


async def upsert_cwe(record: dict[str, Any]) -> None:
    """Insert or update a CWE catalog entry."""
    now = datetime.now(timezone.utc).isoformat()
    consequences = record.get("consequences", [])
    if isinstance(consequences, list):
        consequences = json.dumps(consequences)
    mitigations = record.get("mitigations", [])
    if isinstance(mitigations, list):
        mitigations = json.dumps(mitigations)

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            """
            INSERT INTO cwe (cwe_id, name, description, consequences, mitigations, fetched_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(cwe_id) DO UPDATE SET
                name=excluded.name,
                description=excluded.description,
                consequences=excluded.consequences,
                mitigations=excluded.mitigations,
                fetched_at=excluded.fetched_at
            """,
            (
                record["cwe_id"],
                record.get("name", ""),
                record.get("description", ""),
                consequences,
                mitigations,
                record.get("fetched_at", now),
            ),
        )
        await db.commit()


# ── Report operations ────────────────────────────────────────────────────────

async def get_report(cve_id: str, audience: str = "executive") -> Optional[dict]:
    """Retrieve saved report for a CVE and audience."""
    rows = await query(
        "SELECT * FROM reports WHERE cve_id = ? AND audience = ? ORDER BY id DESC LIMIT 1",
        (cve_id, audience),
    )
    if not rows:
        return None
    r = rows[0]
    if isinstance(r.get("content_json"), str):
        try:
            r["content"] = json.loads(r["content_json"])
        except (json.JSONDecodeError, TypeError):
            r["content"] = {}
    return r


async def get_report_pdf(
    cve_id: str,
    data_hash: str,
    audience: str = "executive",
) -> Optional[bytes]:
    """Return a cached PDF only when it matches the current report evidence hash."""
    rows = await query(
        """
        SELECT pdf_blob FROM reports
        WHERE cve_id = ? AND audience = ? AND data_hash = ?
        ORDER BY id DESC LIMIT 1
        """,
        (cve_id, audience, data_hash),
    )
    return rows[0].get("pdf_blob") if rows else None


async def save_report_pdf(
    cve_id: str,
    data_hash: str,
    pdf_blob: bytes,
    audience: str = "executive",
) -> None:
    """Persist PDF bytes against an existing report with the same evidence hash."""
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            """
            UPDATE reports SET pdf_blob = ?
            WHERE id = (
                SELECT id FROM reports
                WHERE cve_id = ? AND audience = ? AND data_hash = ?
                ORDER BY id DESC LIMIT 1
            )
            """,
            (pdf_blob, cve_id, audience, data_hash),
        )
        if cur.rowcount == 0:
            raise RuntimeError(
                f"Cannot cache PDF for {cve_id}: matching report record was not found"
            )
        await db.commit()


async def upsert_report(
    cve_id: str,
    content_json: str | dict,
    data_hash: str,
    audience: str = "executive",
    pdf_blob: bytes | None = None,
) -> int:
    """Store the latest report and its optional PDF, replacing stale cached data."""
    now = datetime.now(timezone.utc).isoformat()
    raw_json = content_json if isinstance(content_json, str) else json.dumps(content_json)
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "SELECT id FROM reports WHERE cve_id = ? AND audience = ? ORDER BY id DESC LIMIT 1",
            (cve_id, audience),
        )
        existing = await cur.fetchone()
        if existing:
            report_id = existing[0]
            await db.execute(
                """
                UPDATE reports
                SET content_json = ?, data_hash = ?, pdf_blob = ?, created_at = ?
                WHERE id = ?
                """,
                (raw_json, data_hash, pdf_blob, now, report_id),
            )
        else:
            cur = await db.execute(
                """
                INSERT INTO reports (cve_id, audience, content_json, data_hash, pdf_blob, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (cve_id, audience, raw_json, data_hash, pdf_blob, now),
            )
            report_id = cur.lastrowid or 0
        await db.commit()
        return report_id
