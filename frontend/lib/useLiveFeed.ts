"use client";
/**
 * useLiveFeed.ts — SSE live-feed hook with automatic reconnect + polling fallback.
 *
 * Connects to GET /api/stream (SSE) and broadcasts events via a callback.
 * On SSE failure it falls back to polling GET /api/events every pollFallbackMs.
 * Exposes `connectionState`: "live" | "reconnecting" | "offline".
 *
 * Usage:
 *   const { connectionState, lastEventId } = useLiveFeed({
 *     onEvent: (ev) => handleEvent(ev),
 *   });
 */

import { useCallback, useEffect, useRef, useState } from "react";
import { API_BASE } from "./api";

export type ConnectionState = "live" | "reconnecting" | "offline";

export interface LiveEvent {
  id: number;
  event_type: string;
  cve_id: string;
  detail: string;
  created_at?: string;
}

interface UseLiveFeedOptions {
  /** Called for every incoming event */
  onEvent?: (event: LiveEvent) => void;
  /** Interval (ms) for polling fallback when SSE is unavailable. Default 10 000 */
  pollFallbackMs?: number;
  /** Whether the feed should be active. Default true */
  enabled?: boolean;
}

interface UseLiveFeedResult {
  connectionState: ConnectionState;
  lastEventId: number;
}

const MAX_BACKOFF_MS = 30_000;

export function useLiveFeed({
  onEvent,
  pollFallbackMs = 10_000,
  enabled = true,
}: UseLiveFeedOptions = {}): UseLiveFeedResult {
  const [connectionState, setConnectionState] =
    useState<ConnectionState>("reconnecting");
  const [lastEventId, setLastEventId] = useState(0);

  // Stable refs so callbacks don't cause infinite effect loops
  const onEventRef = useRef(onEvent);
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const lastEventIdRef = useRef(0);
  const setLastEventIdBoth = useCallback((id: number) => {
    lastEventIdRef.current = id;
    setLastEventId(id);
  }, []);

  useEffect(() => {
    if (!enabled) return;

    let es: EventSource | null = null;
    let pollTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let backoffMs = 1_000;
    let usingSSE = true;
    let cancelled = false;

    // ── SSE connection ────────────────────────────────────────────────────────
    function connectSSE() {
      if (cancelled) return;
      const url = `${API_BASE}/stream?lastEventId=${lastEventIdRef.current}`;

      try {
        es = new EventSource(url);
      } catch {
        // EventSource not supported or CORS blocked — fall back to polling
        usingSSE = false;
        startPolling();
        return;
      }

      es.onopen = () => {
        if (cancelled) return;
        setConnectionState("live");
        backoffMs = 1_000; // reset backoff on success
      };

      es.onmessage = (ev) => {
        if (cancelled) return;
        try {
          const event: LiveEvent = JSON.parse(ev.data);
          if (ev.lastEventId) {
            setLastEventIdBoth(Number(ev.lastEventId));
          }
          onEventRef.current?.(event);
        } catch {
          // ignore malformed frames
        }
      };

      // Named events (event_type fields from the server)
      const knownEvents = [
        "CVE_ADDED",
        "CVE_MODIFIED",
        "KEV_ADDED",
        "EPSS_UPDATED",
        "PRIORITY_CHANGE",
        "SYNC_ERROR",
        "update",
      ];
      knownEvents.forEach((evtType) => {
        es?.addEventListener(evtType, (ev: MessageEvent) => {
          if (cancelled) return;
          try {
            const event: LiveEvent = JSON.parse(ev.data);
            if ((ev as any).lastEventId) {
              setLastEventIdBoth(Number((ev as any).lastEventId));
            }
            onEventRef.current?.(event);
          } catch {
            // ignore
          }
        });
      });

      es.onerror = () => {
        if (cancelled) return;
        es?.close();
        es = null;
        setConnectionState("reconnecting");
        scheduleReconnect();
      };
    }

    function scheduleReconnect() {
      if (cancelled) return;
      reconnectTimer = setTimeout(() => {
        if (cancelled) return;
        backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
        connectSSE();
      }, backoffMs);
    }

    // ── Polling fallback ──────────────────────────────────────────────────────
    async function pollEvents() {
      if (cancelled) return;
      try {
        const url = `${API_BASE}/events?since_id=${lastEventIdRef.current}&limit=50`;
        const resp = await fetch(url);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const data = await resp.json();
        const events: LiveEvent[] = (data.events ?? []).reverse(); // oldest-first
        for (const ev of events) {
          onEventRef.current?.(ev);
          if (ev.id > lastEventIdRef.current) {
            setLastEventIdBoth(ev.id);
          }
        }
        if (!cancelled) setConnectionState("live");
      } catch {
        if (!cancelled) setConnectionState("offline");
      }
      if (!cancelled) {
        pollTimer = setTimeout(pollEvents, pollFallbackMs);
      }
    }

    function startPolling() {
      setConnectionState("reconnecting");
      pollTimer = setTimeout(pollEvents, 500);
    }

    // ── Detect SSE support ────────────────────────────────────────────────────
    if (typeof EventSource === "undefined") {
      usingSSE = false;
      startPolling();
    } else {
      connectSSE();
    }

    return () => {
      cancelled = true;
      es?.close();
      if (pollTimer) clearTimeout(pollTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      setConnectionState("offline");
    };
  }, [enabled, pollFallbackMs, setLastEventIdBoth]);

  return { connectionState, lastEventId };
}
