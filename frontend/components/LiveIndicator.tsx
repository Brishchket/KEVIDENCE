"use client";
/**
 * LiveIndicator.tsx — Shows real-time connection state and per-source sync health.
 *
 * - Glowing dot + "LIVE" label (green) when SSE is connected
 * - "RECONNECTING" (amber) when recovering
 * - "OFFLINE" (red) when unreachable
 * - Tooltip/popover shows per-source lag (NVD / KEV / EPSS)
 */

import React, { useState } from "react";
import { Wifi, WifiOff, RefreshCw, ChevronDown } from "lucide-react";
import { ConnectionState } from "@/lib/useLiveFeed";
import { SyncStatus } from "@/lib/useSyncStatus";
import { useTheme } from "./ThemeProvider";

interface LiveIndicatorProps {
  connectionState: ConnectionState;
  syncStatus: SyncStatus | null;
}

function formatLag(lagSeconds: number | null): string {
  if (lagSeconds === null) return "N/A";
  if (lagSeconds < 60) return `${Math.round(lagSeconds)}s`;
  if (lagSeconds < 3600) return `${Math.round(lagSeconds / 60)}m`;
  return `${Math.round(lagSeconds / 3600)}h`;
}

const healthColors: Record<string, string> = {
  live: "text-emerald-500",
  degraded: "text-amber-500",
  down: "text-red-500",
};
const healthDot: Record<string, string> = {
  live: "bg-emerald-500",
  degraded: "bg-amber-500",
  down: "bg-red-500",
};

export default function LiveIndicator({
  connectionState,
  syncStatus,
}: LiveIndicatorProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";
  const [open, setOpen] = useState(false);

  const isLive = connectionState === "live";
  const isReconnecting = connectionState === "reconnecting";

  const dotColor = isLive
    ? "bg-emerald-500"
    : isReconnecting
    ? "bg-amber-500"
    : "bg-red-500";

  const label = isLive ? "LIVE" : isReconnecting ? "SYNC" : "OFFLINE";
  const labelColor = isLive
    ? isDark
      ? "text-emerald-400"
      : "text-emerald-700"
    : isReconnecting
    ? isDark
      ? "text-amber-400"
      : "text-amber-700"
    : isDark
    ? "text-red-400"
    : "text-red-700";

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-label="Connection status"
        className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl text-xs font-bold border transition-all shadow-2xs focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${
          isDark
            ? "bg-[#172033] border-[#273449] hover:bg-[#1E293B]"
            : "bg-white border-gray-200 hover:bg-gray-50"
        }`}
      >
        <span
          className={`w-2 h-2 rounded-full ${dotColor} ${
            isLive ? "animate-pulse" : isReconnecting ? "animate-spin" : ""
          }`}
          style={isReconnecting ? { animationDuration: "2s" } : undefined}
        />
        <span className={labelColor}>{label}</span>
        <ChevronDown
          size={12}
          className={isDark ? "text-slate-400" : "text-gray-400"}
        />
      </button>

      {open && (
        <div
          className={`absolute right-0 top-full mt-2 w-64 rounded-xl border shadow-lg z-50 p-3 space-y-2 text-xs ${
            isDark
              ? "bg-[#111827] border-[#273449] text-slate-300"
              : "bg-white border-gray-200 text-gray-700"
          }`}
        >
          <div className="flex items-center justify-between pb-2 border-b border-inherit">
            <span className="font-bold uppercase tracking-wider text-[10px]">
              Feed Status
            </span>
            <span
              className={`font-semibold ${
                isLive ? "text-emerald-500" : "text-amber-500"
              }`}
            >
              {isLive ? "Connected" : isReconnecting ? "Reconnecting…" : "Offline"}
            </span>
          </div>

          {syncStatus
            ? Object.values(syncStatus.sources).map((src) => (
                <div
                  key={src.source}
                  className="flex items-center justify-between"
                >
                  <span className="uppercase font-semibold text-[10px] tracking-wider">
                    {src.source}
                  </span>
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`w-1.5 h-1.5 rounded-full ${
                        healthDot[src.health] ?? "bg-gray-400"
                      }`}
                    />
                    <span className={healthColors[src.health] ?? ""}>
                      {formatLag(src.lag_seconds)} lag
                    </span>
                  </div>
                </div>
              ))
            : ["nvd", "kev", "epss"].map((src) => (
                <div
                  key={src}
                  className="flex items-center justify-between opacity-50"
                >
                  <span className="uppercase font-semibold text-[10px]">{src}</span>
                  <span>—</span>
                </div>
              ))}
        </div>
      )}
    </div>
  );
}
