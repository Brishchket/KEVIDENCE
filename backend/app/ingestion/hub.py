"""
hub.py — In-process pub/sub hub for realtime event broadcasting.

All realtime polling loops call `publish()` with a serialisable event dict.
SSE consumers call `subscribe()` / `unsubscribe()` to get a queue they can
await on.  The hub also maintains a rolling buffer of the last N events so
new subscribers can catch up via Last-Event-ID.
"""
from __future__ import annotations

import asyncio
import logging
from collections import deque
from typing import Any

from app.config import SSE_MAX_BUFFER

logger = logging.getLogger(__name__)


class EventHub:
    """Thread-safe (within a single asyncio event loop) pub/sub hub."""

    def __init__(self, max_buffer: int = SSE_MAX_BUFFER) -> None:
        self._subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self._buffer: deque[dict[str, Any]] = deque(maxlen=max_buffer)
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=200)
        async with self._lock:
            self._subscribers.add(q)
        return q

    async def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            self._subscribers.discard(q)

    async def publish(self, event: dict[str, Any]) -> None:
        """Broadcast event to all live subscribers and append to buffer."""
        async with self._lock:
            self._buffer.append(event)
            dead: list[asyncio.Queue[dict[str, Any]]] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    # Slow consumer — drop the event for them, don't block
                    logger.debug("EventHub: slow consumer, dropping event")
                except Exception:
                    dead.append(q)
            for q in dead:
                self._subscribers.discard(q)

    def get_since(self, since_id: int) -> list[dict[str, Any]]:
        """Return buffered events whose 'id' > since_id, oldest-first."""
        return [e for e in self._buffer if int(e.get("id", 0)) > since_id]

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# Module-level singleton — imported by realtime.py, routers, etc.
hub = EventHub()
