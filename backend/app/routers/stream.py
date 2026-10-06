"""
stream.py — Server-Sent Events (SSE) endpoint for realtime CVE updates.

GET /api/stream
  - Content-Type: text/event-stream
  - Supports Last-Event-ID header for reconnection / catch-up
  - Heartbeat every SSE_HEARTBEAT_INTERVAL seconds
  - CORS-safe (handled at app level)

GET /api/events?since_id=<int>&limit=<int>
  - JSON list of recent events for initial load / polling fallback
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncGenerator

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from app.config import SSE_HEARTBEAT_INTERVAL
from app.db import get_recent_events
from app.ingestion.hub import hub

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["stream"])


async def _sse_generator(request: Request, since_id: int) -> AsyncGenerator[str, None]:
    """Yield SSE-formatted strings until the client disconnects."""
    q = await hub.subscribe()
    try:
        # Initial ping so connection is confirmed immediately
        yield ": connected\n\n"

        # Send buffered catch-up events first
        catch_up = hub.get_since(since_id)
        for ev in catch_up:
            if await request.is_disconnected():
                return
            yield _format_event(ev)

        # Stream live events
        while True:
            if await request.is_disconnected():
                logger.debug("SSE client disconnected")
                return

            try:
                ev = await asyncio.wait_for(q.get(), timeout=SSE_HEARTBEAT_INTERVAL)
                yield _format_event(ev)
            except asyncio.TimeoutError:
                # Heartbeat to keep the connection alive
                yield ": heartbeat\n\n"
    finally:
        await hub.unsubscribe(q)


def _format_event(ev: dict) -> str:
    """Format a dict as an SSE message with id field."""
    lines = []
    if "id" in ev:
        lines.append(f"id: {ev['id']}")
    lines.append(f"event: {ev.get('event_type', 'update')}")
    lines.append(f"data: {json.dumps(ev)}")
    lines.append("")
    lines.append("")
    return "\n".join(lines)


@router.get("/stream")
async def stream_events(
    request: Request,
    last_event_id: str | None = Query(None, alias="lastEventId"),
):
    """Server-Sent Events endpoint for realtime CVE updates."""
    # Parse Last-Event-ID from header (takes precedence) or query param
    header_leid = request.headers.get("Last-Event-ID") or request.headers.get("last-event-id")
    raw_id = header_leid or last_event_id or "0"
    try:
        since_id = int(raw_id)
    except (ValueError, TypeError):
        since_id = 0

    return StreamingResponse(
        _sse_generator(request, since_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/events")
async def get_events(
    since_id: int = Query(0, description="Return events with id > since_id"),
    limit: int = Query(50, ge=1, le=500),
):
    """REST fallback: recent events for initial load or SSE-unavailable clients."""
    events = await get_recent_events(since_id=since_id, limit=limit)
    return {"events": events, "count": len(events)}
