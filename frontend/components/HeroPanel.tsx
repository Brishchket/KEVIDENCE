"use client";
import { useState } from "react";
import { ArrowLeft, ChevronDown, MoreHorizontal } from "lucide-react";
import { SummaryData, VendorsData, FeedData } from "@/lib/api";
import { formatDate, priorityBg } from "@/lib/utils";
import Sparkline from "./Sparkline";
import RadialGauge from "./RadialGauge";

interface HeroPanelProps {
  summary: SummaryData;
  vendors: VendorsData;
  feed: FeedData;
  timeRange: string;
  onTimeRangeChange: (t: string) => void;
}

const SEVERITY_BADGES = [
  { key: "critical" as const, letter: "C", label: "Critical", bg: "bg-[#ED7D24]" },
  { key: "high"     as const, letter: "H", label: "High",     bg: "bg-[#E85D5D]" },
  { key: "medium"   as const, letter: "M", label: "Medium",   bg: "bg-[#F0B429]" },
  { key: "low"      as const, letter: "L", label: "Low",      bg: "bg-[#6BAB8C]" },
];

function eventIcon(type: string) {
  switch (type) {
    case "KEV_ADDED": return "🔴";
    case "PRIORITY_CHANGE": return "⚠️";
    case "CVE_ADDED": return "🆕";
    default: return "📋";
  }
}

export default function HeroPanel({
  summary,
  vendors,
  feed,
  timeRange,
  onTimeRangeChange,
}: HeroPanelProps) {
  const [timeOpen, setTimeOpen] = useState(false);
  const topEvent = feed.events[0];

  return (
    <div
      className="mx-4 mt-3 rounded-2xl overflow-hidden"
      style={{ background: "var(--bg-hero)" }}
    >
      {/* Header row */}
      <div className="flex items-center justify-between px-5 pt-4 pb-2">
        <div className="flex items-center gap-2.5">
          <button
            className="flex items-center justify-center w-7 h-7 rounded-lg bg-white/10 text-white/70 hover:bg-white/20 transition-colors"
            aria-label="Back"
          >
            <ArrowLeft size={14} />
          </button>
          <h1 className="text-white font-semibold text-[15px] tracking-tight">
            Vulnerability Overview
          </h1>
        </div>
        <div className="flex items-center gap-2">
          {/* Live Feed pill */}
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#6BAB8C]/20 text-[#6BAB8C] text-[11px] font-semibold">
            <span className="w-1.5 h-1.5 rounded-full bg-[#6BAB8C] animate-pulse" />
            Live Feed
          </div>
          {/* Time range dropdown */}
          <div className="relative">
            <button
              onClick={() => setTimeOpen(!timeOpen)}
              className="flex items-center gap-1 px-2.5 py-1 rounded-lg bg-white/10 text-white/80 text-[11px] font-medium hover:bg-white/15 transition-colors"
            >
              {timeRange}
              <ChevronDown size={12} />
            </button>
            {timeOpen && (
              <div className="absolute right-0 top-full mt-1 z-50 bg-[#0D1A16] border border-[#1E3A30] rounded-xl overflow-hidden shadow-xl">
                {["24h", "7d", "30d"].map((t) => (
                  <button
                    key={t}
                    onClick={() => { onTimeRangeChange(t); setTimeOpen(false); }}
                    className={`block w-full px-4 py-2 text-[12px] text-left hover:bg-[#1E3A30] ${
                      timeRange === t ? "text-[#ED7D24]" : "text-white/70"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            )}
          </div>
          <button className="p-1.5 rounded-lg bg-white/10 text-white/60 hover:bg-white/15" aria-label="More options">
            <MoreHorizontal size={14} />
          </button>
        </div>
      </div>

      {/* 3-column body */}
      <div className="grid grid-cols-1 md:grid-cols-[200px_1fr_220px] gap-0 px-5 pb-5 pt-2">
        {/* LEFT: Stats */}
        <div className="flex flex-col gap-4 py-2 pr-4">
          <div>
            <p className="text-[#8A9E95] text-[11px] font-medium uppercase tracking-widest mb-0.5">
              CVEs Ingested
            </p>
            <div className="flex items-baseline gap-1.5">
              <span className="text-white font-bold tabular-nums" style={{ fontSize: 38, lineHeight: 1 }}>
                {summary.total.toLocaleString()}
              </span>
              <span className="text-[#8A9E95] text-[13px]">Total</span>
            </div>
            <div className="mt-2 w-full">
              <Sparkline data={summary.trend || []} />
            </div>
          </div>

          <div>
            <p className="text-[#8A9E95] text-[11px] font-medium uppercase tracking-widest mb-2">
              Open Vulnerabilities
            </p>
            <div className="flex items-center gap-2.5">
              {SEVERITY_BADGES.map(({ key, letter, label, bg }) => (
                <div key={key} className="flex flex-col items-center gap-1">
                  <div
                    className={`w-8 h-8 rounded-full ${bg} flex items-center justify-center text-white font-bold text-[13px] shadow-sm`}
                    title={label}
                    aria-label={`${label}: ${summary[key]}`}
                  >
                    {letter}
                  </div>
                  <span className="text-white/80 text-[11px] tabular-nums font-semibold">
                    {summary[key]}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* CENTER: Radial gauge */}
        <div className="flex items-center justify-center min-h-[200px]">
          <RadialGauge
            total={summary.total}
            pctBelowMedium={summary.pct_below_medium || 0}
            vendors={vendors.vendors || []}
          />
        </div>

        {/* RIGHT: Feed */}
        <div className="flex flex-col gap-0 pl-3 border-l border-white/10">
          <p className="text-[#8A9E95] text-[11px] font-medium uppercase tracking-widest mb-2 mt-2">
            Recent Events
          </p>
          <div className="flex flex-col gap-1 overflow-y-auto max-h-[200px] pr-1">
            {feed.events.length === 0 && (
              <p className="text-[#5A6B62] text-[12px] italic">No events yet. Run ingestion first.</p>
            )}
            {feed.events.map((ev, i) => (
              <div
                key={ev.id}
                className={`flex items-start gap-2 px-3 py-2 rounded-lg text-[12px] ${
                  i === 0
                    ? "bg-[#ED7D24] text-white font-semibold"
                    : "bg-white/5 text-white/75"
                }`}
              >
                <span className="shrink-0 mt-px">{eventIcon(ev.event_type)}</span>
                <div className="min-w-0">
                  <p className="truncate leading-tight">{ev.detail}</p>
                  <p className={`text-[10px] mt-0.5 ${i === 0 ? "text-white/80" : "text-white/40"}`}>
                    {ev.cve_id}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
