"""
realtime.py — Continuously running asyncio supervisor for PhantomPatch.

Three independent polling loops:
  a. NVD delta loop  — watermark-based incremental fetch (lastModStartDate)
  b. KEV loop        — ETag/content-hash deduplication
  c. EPSS loop       — periodic refresh of all CVEs in DB + immediate fetch
                       for brand-new CVEs discovered by loop (a)

All loops:
  • Catch, log, and back off on any exception — the supervisor never crashes.
  • Respect NVD_RATE_LIMIT_DELAY and config-driven intervals.
  • Write pipeline_runs rows for parse-rate stats.
  • Publish events to the in-process EventHub so SSE consumers see them.
  • Update sync_state (watermark, consecutive_failures, last_error).

Optional: AUTO_NARRATE_NEW — auto-generate narratives for new CRITICAL/HIGH.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.config import (
    AUTO_NARRATE_NEW,
    AUTO_NARRATE_RATE_LIMIT,
    EPSS_BATCH_SIZE,
    EPSS_POLL_INTERVAL,
    KEV_POLL_INTERVAL,
    NVD_DATE_WINDOW_DAYS,
    NVD_POLL_INTERVAL,
    NVD_RATE_LIMIT_DELAY,
)
from app.db import (
    create_run,
    finish_run,
    get_all_kev_ids,
    get_all_sync_states,
    get_cve,
    get_cves,
    get_sync_state,
    log_event,
    upsert_cve,
    upsert_epss,
    upsert_kev,
    upsert_sync_state,
)
from app.ingestion.epss import fetch_epss_scores
from app.ingestion.hub import hub
from app.ingestion.kev import fetch_kev_catalog
from app.ingestion.parser import parse_cve
from app.scoring.scorer import prioritize

logger = logging.getLogger(__name__)

# ── Event type constants ───────────────────────────────────────────────────────

EVT_CVE_ADDED = "CVE_ADDED"
EVT_CVE_MODIFIED = "CVE_MODIFIED"
EVT_KEV_ADDED = "KEV_ADDED"
EVT_EPSS_UPDATED = "EPSS_UPDATED"
EVT_PRIORITY_CHANGE = "PRIORITY_CHANGE"
EVT_SYNC_ERROR = "SYNC_ERROR"

SOURCE_NVD = "nvd"
SOURCE_KEV = "kev"
SOURCE_EPSS = "epss"


# ── Shared state for cross-loop communication ─────────────────────────────────

_new_cve_ids: asyncio.Queue[str] = asyncio.Queue()  # NVD loop → EPSS loop


# ── Helper: publish + log ─────────────────────────────────────────────────────

async def _emit(event_type: str, cve_id: str, detail: str) -> None:
    """Persist event to DB and broadcast via hub."""
    row_id = await log_event(event_type, cve_id, detail)
    await hub.publish({
        "id": row_id,
        "event_type": event_type,
        "cve_id": cve_id,
        "detail": detail,
        "created_at": datetime.now(timezone.utc).isoformat(),
    })


# ── Helper: content hash ──────────────────────────────────────────────────────

def _content_hash(obj: dict[str, Any]) -> str:
    """Stable hash of the fields we care about for change detection."""
    key_fields = (
        "cvss_base_score", "cvss_vector", "severity", "attack_vector",
        "epss_score", "epss_percentile", "in_kev", "last_modified_date",
        "description",
    )
    sig = {k: obj.get(k) for k in key_fields}
    return hashlib.sha1(json.dumps(sig, sort_keys=True).encode()).hexdigest()


# ── Helper: NVD delta fetch ───────────────────────────────────────────────────

async def _fetch_nvd_delta(
    start_dt: datetime,
    end_dt: datetime,
) -> list[dict[str, Any]]:
    """Yield raw CVE dicts from NVD using lastMod dates (not pubDate)."""
    from app.config import NVD_API_KEY, NVD_BASE_URL, NVD_RESULTS_PER_PAGE
    from app.ingestion.nvd import NVDRateLimitError, _fetch_page
    import httpx

    fmt = "%Y-%m-%dT%H:%M:%S.000"
    headers: dict[str, str] = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    results: list[dict[str, Any]] = []
    # Chunk the date range the same way the batch pipeline does
    window = timedelta(days=NVD_DATE_WINDOW_DAYS)
    current = start_dt
    async with httpx.AsyncClient(follow_redirects=True, headers=headers) as client:
        while current < end_dt:
            chunk_end = min(current + window, end_dt)
            start_index = 0
            total_results: int | None = None

            while True:
                params: dict[str, Any] = {
                    "lastModStartDate": current.strftime(fmt),
                    "lastModEndDate": chunk_end.strftime(fmt),
                    "resultsPerPage": NVD_RESULTS_PER_PAGE,
                    "startIndex": start_index,
                }
                try:
                    data = await _fetch_page(client, params)
                except NVDRateLimitError as exc:
                    logger.warning("NVD rate limit in delta fetch: %s", exc)
                    await asyncio.sleep(NVD_RATE_LIMIT_DELAY * 2)
                    continue

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    logger.debug("NVD delta: %d CVEs in window %s→%s",
                                 total_results, current.date(), chunk_end.date())

                for item in data.get("vulnerabilities", []):
                    results.append(item.get("cve", {}))

                start_index += len(data.get("vulnerabilities", []))
                if start_index >= (total_results or 0) or not data.get("vulnerabilities"):
                    break
                await asyncio.sleep(NVD_RATE_LIMIT_DELAY)

            current = chunk_end
            if current < end_dt:
                await asyncio.sleep(NVD_RATE_LIMIT_DELAY)

    return results


# ── Loop a: NVD delta ─────────────────────────────────────────────────────────

async def nvd_delta_loop() -> None:
    """
    Continuously poll NVD for CVEs modified since the last successful run.
    Uses a persisted watermark in sync_state.last_cursor.
    """
    logger.info("NVD delta loop started (interval=%ds)", NVD_POLL_INTERVAL)

    while True:
        try:
            state = await get_sync_state(SOURCE_NVD)
            failures = (state or {}).get("consecutive_failures", 0)

            # Watermark: last successful cursor or 2 hours ago (initial bootstrap)
            cursor_str = (state or {}).get("last_cursor")
            if cursor_str:
                since = datetime.fromisoformat(cursor_str)
            else:
                since = datetime.now(timezone.utc) - timedelta(hours=2)

            now = datetime.now(timezone.utc)

            # Nothing to do if cursor is very recent (< 30s old)
            if (now - since).total_seconds() < 30:
                await asyncio.sleep(NVD_POLL_INTERVAL)
                continue

            logger.info("NVD delta: fetching CVEs modified %s → %s", since, now)
            run_id = await create_run(since.isoformat(), now.isoformat())

            raw_cves = await _fetch_nvd_delta(since, now)
            logger.info("NVD delta: got %d raw CVEs", len(raw_cves))

            # Batch EPSS for these CVEs
            cve_ids = [r.get("id", "") for r in raw_cves if r.get("id")]
            epss_scores: dict[str, Any] = {}
            if cve_ids:
                epss_scores = await fetch_epss_scores(cve_ids)

            # Current KEV set (cheap — already in DB)
            kev_ids = await get_all_kev_ids()

            inserted = updated = parse_failures = 0
            attempted = len(raw_cves)

            for raw in raw_cves:
                cid = raw.get("id", "")
                epss_data = epss_scores.get(cid)
                kev_record = None  # KEV loop handles KEV upserts separately

                # Build minimal kev_record from DB if in KEV
                in_kev = cid in kev_ids

                parsed = parse_cve(raw, epss_data=epss_data,
                                   kev_record={"cve_id": cid} if in_kev else None)
                if parsed is None:
                    parse_failures += 1
                    continue

                # Check if content changed before writing
                existing = await get_cve(cid)
                new_hash = _content_hash(parsed)
                if existing and _content_hash(existing) == new_hash:
                    continue  # no change — skip write

                scored = prioritize(parsed)
                is_new = await upsert_cve(scored)

                if is_new:
                    inserted += 1
                    await _emit(EVT_CVE_ADDED, cid,
                                f"New CVE — {scored.get('priority_label')}")
                    # Notify EPSS loop about new CVE
                    await _new_cve_ids.put(cid)
                    # Optional auto-narrate
                    if AUTO_NARRATE_NEW and scored.get("priority_label") in ("CRITICAL", "HIGH"):
                        asyncio.create_task(_auto_narrate(cid))
                else:
                    updated += 1
                    await _emit(EVT_CVE_MODIFIED, cid,
                                f"CVE updated — {scored.get('priority_label')}")

                # EPSS upsert from enriched data
                if epss_data:
                    await upsert_epss(cid, epss_data["probability"], epss_data["percentile"])

            parse_rate = ((attempted - parse_failures) / attempted * 100) if attempted else 0.0
            await finish_run(run_id, len(raw_cves), "COMPLETE", parse_failures, round(parse_rate, 2))

            new_cursor = now.isoformat()
            await upsert_sync_state(
                SOURCE_NVD,
                last_success_at=new_cursor,
                last_cursor=new_cursor,
                last_error=None,
                consecutive_failures=0,
            )
            logger.info("NVD delta: inserted=%d updated=%d failures=%d parse_rate=%.1f%%",
                        inserted, updated, parse_failures, parse_rate)

        except asyncio.CancelledError:
            logger.info("NVD delta loop cancelled")
            return
        except Exception as exc:
            logger.exception("NVD delta loop error: %s", exc)
            state = await get_sync_state(SOURCE_NVD)
            failures = ((state or {}).get("consecutive_failures") or 0) + 1
            await upsert_sync_state(
                SOURCE_NVD,
                last_error=str(exc),
                consecutive_failures=failures,
            )
            await _emit(EVT_SYNC_ERROR, "", f"NVD sync error: {exc}")
            # Exponential backoff capped at 10 min
            backoff = min(NVD_POLL_INTERVAL * 2 ** min(failures, 4), 600)
            logger.info("NVD delta loop backing off %ds (failures=%d)", backoff, failures)
            await asyncio.sleep(backoff)
            continue

        await asyncio.sleep(NVD_POLL_INTERVAL)


# ── Loop b: KEV ───────────────────────────────────────────────────────────────

async def kev_loop() -> None:
    """
    Poll CISA KEV using a content hash to avoid redundant DB writes.
    When a CVE newly appears in KEV, flip in_kev, re-prioritize, emit KEV_ADDED.
    """
    import httpx
    logger.info("KEV loop started (interval=%ds)", KEV_POLL_INTERVAL)
    last_hash: str | None = None

    while True:
        try:
            # Download KEV (uses If-None-Match / content hash)
            async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
                resp = await client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=60,
                )
                resp.raise_for_status()
                raw_body = resp.content
                current_hash = hashlib.sha1(raw_body).hexdigest()

            if current_hash == last_hash:
                logger.debug("KEV unchanged (hash %s)", current_hash[:8])
                await upsert_sync_state(
                    SOURCE_KEV,
                    last_success_at=datetime.now(timezone.utc).isoformat(),
                    consecutive_failures=0,
                    last_error=None,
                )
                await asyncio.sleep(KEV_POLL_INTERVAL)
                continue

            last_hash = current_hash
            catalog = {}
            data = resp.json()
            for v in data.get("vulnerabilities", []):
                cid = v.get("cveID", "")
                if cid:
                    catalog[cid] = {
                        "cve_id": cid,
                        "vendor_project": v.get("vendorProject"),
                        "product": v.get("product"),
                        "vulnerability_name": v.get("vulnerabilityName"),
                        "date_added": v.get("dateAdded"),
                        "due_date": v.get("dueDate"),
                        "required_action": v.get("requiredAction"),
                        "known_ransomware_use": v.get("knownRansomwareCampaignUse"),
                        "short_description": v.get("shortDescription"),
                    }

            logger.info("KEV catalog refreshed: %d entries", len(catalog))

            # Upsert all KEV records
            for cid, kev_rec in catalog.items():
                await upsert_kev(kev_rec)

            # Check which CVEs in our DB are newly KEV-listed
            prev_kev_ids = await get_all_kev_ids()
            for cid in catalog:
                existing_cve = await get_cve(cid)
                if existing_cve is None:
                    continue
                if not existing_cve.get("in_kev"):
                    # Newly added to KEV — update the CVE record
                    updated_cve = dict(existing_cve)
                    updated_cve["in_kev"] = True
                    old_label = existing_cve.get("priority_label", "LOW")
                    scored = prioritize(updated_cve)
                    await upsert_cve(scored)
                    await _emit(EVT_KEV_ADDED, cid,
                                f"CVE added to CISA KEV catalog")
                    if scored.get("priority_label") != old_label:
                        await _emit(EVT_PRIORITY_CHANGE, cid,
                                    f"Priority: {old_label} → {scored.get('priority_label')}")
                    if AUTO_NARRATE_NEW and scored.get("priority_label") in ("CRITICAL", "HIGH"):
                        asyncio.create_task(_auto_narrate(cid))

            await upsert_sync_state(
                SOURCE_KEV,
                last_success_at=datetime.now(timezone.utc).isoformat(),
                last_cursor=current_hash,
                consecutive_failures=0,
                last_error=None,
            )

        except asyncio.CancelledError:
            logger.info("KEV loop cancelled")
            return
        except Exception as exc:
            logger.exception("KEV loop error: %s", exc)
            state = await get_sync_state(SOURCE_KEV)
            failures = ((state or {}).get("consecutive_failures") or 0) + 1
            await upsert_sync_state(
                SOURCE_KEV,
                last_error=str(exc),
                consecutive_failures=failures,
            )
            await _emit(EVT_SYNC_ERROR, "", f"KEV sync error: {exc}")
            backoff = min(KEV_POLL_INTERVAL * 2 ** min(failures, 4), 1800)
            logger.info("KEV loop backing off %ds", backoff)
            await asyncio.sleep(backoff)
            continue

        await asyncio.sleep(KEV_POLL_INTERVAL)


# ── Loop c: EPSS ──────────────────────────────────────────────────────────────

async def epss_loop() -> None:
    """
    Two responsibilities:
    1. Periodic full refresh of EPSS for all CVEs in DB (EPSS_POLL_INTERVAL).
    2. Immediate fetch for brand-new CVE IDs signalled by the NVD delta loop.
    """
    logger.info("EPSS loop started (interval=%ds)", EPSS_POLL_INTERVAL)
    next_full_refresh = asyncio.get_event_loop().time()

    while True:
        try:
            now_loop = asyncio.get_event_loop().time()

            # --- Immediate fetch for new CVEs ---
            new_ids: list[str] = []
            while True:
                try:
                    cid = _new_cve_ids.get_nowait()
                    new_ids.append(cid)
                except asyncio.QueueEmpty:
                    break

            if new_ids:
                logger.info("EPSS immediate fetch for %d new CVEs", len(new_ids))
                try:
                    scores = await fetch_epss_scores(new_ids)
                    for cid, epss_data in scores.items():
                        await upsert_epss(cid, epss_data["probability"], epss_data["percentile"])
                        # Also update the cves table epss_score column
                        existing = await get_cve(cid)
                        if existing:
                            existing["epss_score"] = epss_data["probability"]
                            existing["epss_percentile"] = epss_data["percentile"]
                            scored = prioritize(existing)
                            old_label = existing.get("priority_label", "LOW")
                            await upsert_cve(scored)
                            await _emit(EVT_EPSS_UPDATED, cid,
                                        f"EPSS updated to {epss_data['probability']:.4f}")
                            if scored.get("priority_label") != old_label:
                                await _emit(EVT_PRIORITY_CHANGE, cid,
                                            f"Priority: {old_label} → {scored.get('priority_label')}")
                except Exception as exc:
                    logger.error("EPSS immediate fetch error: %s", exc)

            # --- Periodic full refresh ---
            if now_loop >= next_full_refresh:
                logger.info("EPSS full refresh starting...")
                try:
                    rows, total = await get_cves(limit=10000, offset=0)
                    all_ids = [r["cve_id"] for r in rows]
                    if all_ids:
                        for i in range(0, len(all_ids), EPSS_BATCH_SIZE):
                            batch = all_ids[i: i + EPSS_BATCH_SIZE]
                            scores = await fetch_epss_scores(batch)
                            for cid, epss_data in scores.items():
                                await upsert_epss(cid, epss_data["probability"],
                                                  epss_data["percentile"])
                                existing = await get_cve(cid)
                                if existing:
                                    old_label = existing.get("priority_label", "LOW")
                                    existing["epss_score"] = epss_data["probability"]
                                    existing["epss_percentile"] = epss_data["percentile"]
                                    scored = prioritize(existing)
                                    await upsert_cve(scored)
                                    if scored.get("priority_label") != old_label:
                                        await _emit(EVT_PRIORITY_CHANGE, cid,
                                                    f"Priority: {old_label} → {scored.get('priority_label')}")
                    logger.info("EPSS full refresh done for %d CVEs", len(all_ids))
                    await upsert_sync_state(
                        SOURCE_EPSS,
                        last_success_at=datetime.now(timezone.utc).isoformat(),
                        consecutive_failures=0,
                        last_error=None,
                    )
                except Exception as exc:
                    logger.error("EPSS full refresh error: %s", exc)
                    state = await get_sync_state(SOURCE_EPSS)
                    failures = ((state or {}).get("consecutive_failures") or 0) + 1
                    await upsert_sync_state(
                        SOURCE_EPSS,
                        last_error=str(exc),
                        consecutive_failures=failures,
                    )

                next_full_refresh = now_loop + EPSS_POLL_INTERVAL

        except asyncio.CancelledError:
            logger.info("EPSS loop cancelled")
            return
        except Exception as exc:
            logger.exception("EPSS loop unexpected error: %s", exc)

        await asyncio.sleep(10)  # tight inner loop; actual cadence via next_full_refresh


# ── Auto-narrate helper ────────────────────────────────────────────────────────

_auto_narrate_semaphore = asyncio.Semaphore(AUTO_NARRATE_RATE_LIMIT)


async def _auto_narrate(cve_id: str) -> None:
    """Generate narratives for a CVE in the background (rate-limited)."""
    async with _auto_narrate_semaphore:
        try:
            from app.evidence.builder import build_evidence
            from app.narrative.generator import generate_narrative, get_llm_client
            evidence = await build_evidence(cve_id)
            if evidence is None:
                return
            llm_client = get_llm_client()
            for audience in ("manager", "analyst", "it_admin"):
                await generate_narrative(evidence, audience, llm_client)
            logger.info("Auto-narrated %s", cve_id)
        except Exception as exc:
            logger.warning("Auto-narrate failed for %s: %s", cve_id, exc)


# ── Supervisor ────────────────────────────────────────────────────────────────

_supervisor_tasks: list[asyncio.Task[None]] = []


async def start_supervisor() -> None:
    """Start all polling loops as independent asyncio Tasks."""
    global _supervisor_tasks
    logger.info("Starting realtime supervisor (NVD/KEV/EPSS loops)")
    _supervisor_tasks = [
        asyncio.create_task(nvd_delta_loop(), name="nvd-delta"),
        asyncio.create_task(kev_loop(), name="kev-loop"),
        asyncio.create_task(epss_loop(), name="epss-loop"),
    ]
    logger.info("Realtime supervisor started: %d tasks", len(_supervisor_tasks))


async def stop_supervisor() -> None:
    """Cancel all running polling tasks and wait for them to finish."""
    global _supervisor_tasks
    logger.info("Stopping realtime supervisor...")
    for task in _supervisor_tasks:
        task.cancel()
    if _supervisor_tasks:
        await asyncio.gather(*_supervisor_tasks, return_exceptions=True)
    _supervisor_tasks = []
    logger.info("Realtime supervisor stopped")
