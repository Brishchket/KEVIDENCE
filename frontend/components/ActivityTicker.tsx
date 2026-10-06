"use client";
/**
 * ActivityTicker.tsx — Scrolling live activity feed showing recent events.
 *
 * Displays KEV_ADDED, PRIORITY_CHANGE, CVE_ADDED events with lucide icons.
 * Respects prefers-reduced-motion.
 */

import React, { useEffect, useRef, useState } from "react";
import {
  Flame,
  TrendingUp,
  Plus,
  AlertTriangle,
  RefreshCw,
  Activity,
} from "lucide-react";
import { LiveEvent } from "@/lib/useLiveFeed";
import { useTheme } from "./ThemeProvider";

interface ActivityTickerProps {
  events: LiveEvent[];
  maxItems?: number;
}

const EVENT_ICONS: Record<string, React.ReactNode> = {
  KEV_ADDED: <Flame size={13} className="text-red-500 shrink-0" />,
  PRIORITY_CHANGE: <TrendingUp size={13} className="text-purple-500 shrink-0" />,
  CVE_ADDED: <Plus size={13} className="text-emerald-500 shrink-0" />,
  CVE_MODIFIED: <RefreshCw size={13} className="text-blue-500 shrink-0" />,
  EPSS_UPDATED: <Activity size={13} className="text-amber-500 shrink-0" />,
  SYNC_ERROR: <AlertTriangle size={13} className="text-red-400 shrink-0" />,
};

const EVENT_COLORS: Record<string, string> = {
  KEV_ADDED: "text-red-600 dark:text-red-400",
  PRIORITY_CHANGE: "text-purple-700 dark:text-purple-400",
  CVE_ADDED: "text-emerald-700 dark:text-emerald-400",
  CVE_MODIFIED: "text-blue-700 dark:text-blue-400",
  EPSS_UPDATED: "text-amber-700 dark:text-amber-400",
  SYNC_ERROR: "text-red-500 dark:text-red-400",
};

function formatTime(isoString?: string): string {
  if (!isoString) return "";
  try {
    const d = new Date(isoString);
    return d.toLocaleTimeString(undefined, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return "";
  }
}

export default function ActivityTicker({
  events,
  maxItems = 8,
}: ActivityTickerProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const listRef = useRef<HTMLUListElement>(null);

  // Respect prefers-reduced-motion
  const [reduceMotion, setReduceMotion] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    setReduceMotion(mq.matches);
    const handler = (e: MediaQueryListEvent) => setReduceMotion(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  // Auto-scroll to latest when new events arrive (unless reduced motion)
  useEffect(() => {
    if (!reduceMotion && listRef.current) {
      listRef.current.scrollTop = 0;
    }
  }, [events, reduceMotion]);

  const visibleEvents = events.slice(0, maxItems);

  return (
    <div
      className={`rounded-xl border p-3 space-y-1 ${
        isDark
          ? "bg-[#111827] border-[#273449]"
          : "bg-white border-gray-200"
      }`}
    >
      <div className="flex items-center gap-2 mb-2">
        <Activity
          size={14}
          className={isDark ? "text-emerald-400" : "text-emerald-600"}
        />
        <span
          className={`text-[11px] font-bold uppercase tracking-wider ${
            isDark ? "text-slate-400" : "text-gray-500"
          }`}
        >
          Live Activity
        </span>
      </div>

      {visibleEvents.length === 0 ? (
        <p
          className={`text-xs italic ${
            isDark ? "text-slate-500" : "text-gray-400"
          }`}
        >
          Waiting for events…
        </p>
      ) : (
        <ul
          ref={listRef}
          className="space-y-1 max-h-48 overflow-y-auto"
          aria-live="polite"
          aria-label="Live activity feed"
        >
          {visibleEvents.map((ev) => (
            <li
              key={ev.id}
              className={`flex items-start gap-2 text-[11px] py-1 px-1.5 rounded-lg ${
                reduceMotion ? "" : "transition-colors"
              } ${
                isDark
                  ? "hover:bg-[#1E293B]"
                  : "hover:bg-gray-50"
              }`}
            >
              {EVENT_ICONS[ev.event_type] ?? (
                <Activity size={13} className="text-gray-400 shrink-0" />
              )}
              <div className="flex-1 min-w-0">
                <span
                  className={`font-bold truncate block ${
                    EVENT_COLORS[ev.event_type] ?? ""
                  }`}
                >
                  {ev.cve_id || "System"}
                </span>
                <span
                  className={`truncate block ${
                    isDark ? "text-slate-400" : "text-gray-500"
                  }`}
                >
                  {ev.detail}
                </span>
              </div>
              <span
                className={`text-[10px] font-mono shrink-0 ${
                  isDark ? "text-slate-600" : "text-gray-400"
                }`}
              >
                {formatTime(ev.created_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
