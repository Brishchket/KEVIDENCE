"use client";
/**
 * useSyncStatus.ts — Polls /api/sync/status and returns per-source health.
 */

import { useEffect, useRef, useState } from "react";
import { API_BASE } from "./api";

export type SourceHealth = "live" | "degraded" | "down";

export interface SourceStatus {
  source: string;
  last_success_at: string | null;
  lag_seconds: number | null;
  consecutive_failures: number;
  last_error: string | null;
  health: SourceHealth;
}

export interface SyncStatus {
  sources: Record<string, SourceStatus>;
  checked_at: string;
}

export function useSyncStatus(pollMs = 30_000) {
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function fetch_status() {
      try {
        const resp = await fetch(`${API_BASE}/sync/status`);
        if (!resp.ok) return;
        const data: SyncStatus = await resp.json();
        if (!cancelled) setStatus(data);
      } catch {
        // ignore transient network errors
      }
      if (!cancelled) {
        timerRef.current = setTimeout(fetch_status, pollMs);
      }
    }

    fetch_status();
    return () => {
      cancelled = true;
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [pollMs]);

  return status;
}
