"""
sync_status.py — Sync health and status endpoints.

GET /api/sync/status
  Returns per-source health: last_success_at, lag_seconds, consecutive_failures,
  health (live / degraded / down).
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter

from app.db import get_all_sync_states

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sync", tags=["sync"])

_DEGRADED_THRESHOLD = 2   # consecutive failures before "degraded"
_DOWN_THRESHOLD = 5        # consecutive failures before "down"

# Expected maximum lag (seconds) per source before calling "degraded"
_MAX_LAG: dict[str, int] = {
    "nvd": 300,    # 5 min — 2× NVD_POLL_INTERVAL default
    "kev": 900,    # 15 min — 3× KEV_POLL_INTERVAL default
    "epss": 7200,  # 2 h — well within EPSS_POLL_INTERVAL default
}


def _health(source: str, row: dict) -> str:
    failures = row.get("consecutive_failures", 0) or 0
    if failures >= _DOWN_THRESHOLD:
        return "down"
    if failures >= _DEGRADED_THRESHOLD:
        return "degraded"
    last_ok = row.get("last_success_at")
    if last_ok:
        try:
            dt = datetime.fromisoformat(last_ok)
            lag = (datetime.now(timezone.utc) - dt).total_seconds()
            max_lag = _MAX_LAG.get(source, 3600)
            if lag > max_lag * 3:
                return "down"
            if lag > max_lag:
                return "degraded"
        except ValueError:
            pass
    if last_ok is None:
        return "degraded"
    return "live"


@router.get("/status")
async def sync_status():
    """Return per-source sync health information."""
    rows = await get_all_sync_states()
    row_map = {r["source"]: r for r in rows}
    sources = ["nvd", "kev", "epss"]
    now = datetime.now(timezone.utc)

    result: dict[str, dict] = {}
    for src in sources:
        row = row_map.get(src, {})
        last_ok = row.get("last_success_at")
        lag: float | None = None
        if last_ok:
            try:
                dt = datetime.fromisoformat(last_ok)
                lag = round((now - dt).total_seconds(), 1)
            except ValueError:
                pass
        result[src] = {
            "source": src,
            "last_success_at": last_ok,
            "lag_seconds": lag,
            "consecutive_failures": row.get("consecutive_failures", 0) or 0,
            "last_error": row.get("last_error"),
            "health": _health(src, row),
        }

    return {"sources": result, "checked_at": now.isoformat()}
