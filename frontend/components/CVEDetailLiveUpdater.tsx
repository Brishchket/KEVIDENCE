"use client";
/**
 * CVEDetailLiveUpdater.tsx — Client component that listens for live events
 * affecting the current CVE and triggers a page refresh when detected.
 *
 * The CVE detail page is a server component — we can't inject SSE there
 * directly. Instead we mount this tiny client component that watches the
 * SSE stream and calls router.refresh() when the CVE changes, which causes
 * Next.js to re-render the server component in place without a full reload.
 *
 * Respects prefers-reduced-motion: shows a brief notification rather than
 * instantly refreshing when the user may be scrolling/reading.
 */

import React, { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useLiveFeedContext } from "./LiveFeedContext";
import { RefreshCw, X } from "lucide-react";

interface Props {
  cveId: string;
}

export default function CVEDetailLiveUpdater({ cveId }: Props) {
  const router = useRouter();
  const [hasPending, setHasPending] = useState(false);
  const [reduceMotion, setReduceMotion] = useState(false);
  const lastEventIdRef = useRef(0);

  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduceMotion(mq.matches);
    const h = (e: MediaQueryListEvent) => setReduceMotion(e.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, []);

  // Watch for events affecting this CVE via shared context
  const { recentEvents } = useLiveFeedContext();
  useEffect(() => {
    if (!recentEvents.length) return;
    const latest = recentEvents[0];
    if (
      latest.id !== lastEventIdRef.current &&
      latest.cve_id === cveId &&
      ["CVE_ADDED", "CVE_MODIFIED", "KEV_ADDED", "EPSS_UPDATED", "PRIORITY_CHANGE"].includes(
        latest.event_type
      )
    ) {
      lastEventIdRef.current = latest.id;
      if (reduceMotion) {
        setHasPending(true);
      } else {
        router.refresh();
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recentEvents]);

  if (!hasPending) return null;

  return (
    <div
      role="alert"
      className="fixed bottom-6 right-6 z-50 flex items-center gap-3 px-4 py-3 rounded-xl bg-emerald-900 text-emerald-100 shadow-lg border border-emerald-700"
    >
      <RefreshCw size={16} className="text-emerald-300" />
      <span className="text-sm font-semibold">This CVE was updated. Refresh to see changes.</span>
      <button
        onClick={() => {
          setHasPending(false);
          router.refresh();
        }}
        className="ml-2 px-3 py-1 text-xs font-bold bg-emerald-700 hover:bg-emerald-600 rounded-lg transition-colors"
      >
        Refresh
      </button>
      <button
        onClick={() => setHasPending(false)}
        aria-label="Dismiss"
        className="ml-1 text-emerald-400 hover:text-emerald-200"
      >
        <X size={14} />
      </button>
    </div>
  );
}
