"use client";
import React from "react";
import { Clock, ShieldCheck, Database, RefreshCw, Activity } from "lucide-react";
import { formatDate } from "@/lib/utils";
import { useTheme } from "./ThemeProvider";

interface LastUpdatedProps {
  lastUpdated?: {
    nvd?: string | null;
    epss?: string | null;
    kev?: string | null;
  };
  parseRate?: number;
  theme?: "light" | "dark";
}

export default function LastUpdatedPanel({ lastUpdated, parseRate = 100, theme: propTheme }: LastUpdatedProps) {
  const { theme: contextTheme } = useTheme();
  const theme = propTheme || contextTheme || "light";
  const isDark = theme === "dark";

  const sources = [
    {
      name: "NVD (NIST CVE Feed)",
      type: "Vulnerability Definitions & CVSS v3.1",
      timestamp: lastUpdated?.nvd ?? null,
      status: "Synced",
      badge: "Primary Corpus",
    },
    {
      name: "FIRST.Org EPSS API",
      type: "Daily Exploit Prediction Probabilities",
      timestamp: lastUpdated?.epss ?? null,
      status: "Active Feed",
      badge: "v3 Scoring",
    },
    {
      name: "CISA KEV Catalog",
      type: "Known Exploited Vulnerabilities Database",
      timestamp: lastUpdated?.kev ?? null,
      status: "Authoritative",
      badge: "Weaponized",
    },
  ];

  return (
    <div
      className={`rounded-2xl border p-6 flex flex-col justify-between transition-colors ${
        isDark
          ? "bg-slate-900 border-slate-800 shadow-md text-slate-100"
          : "bg-white border-gray-200/90 shadow-2xs text-gray-900"
      }`}
    >
      <div>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <div className={`p-2 rounded-xl ${isDark ? "bg-orange-950/60 text-[#F59E0B]" : "bg-orange-50 text-[#ED7D24]"}`}>
              <Database size={18} />
            </div>
            <div>
              <h3 className={`text-base font-bold tracking-tight ${isDark ? "text-white" : "text-gray-900"}`}>
                Intelligence Feeds
              </h3>
              <p className={`text-xs ${isDark ? "text-slate-400" : "text-gray-500"}`}>
                Live source ingestion & synchronization status
              </p>
            </div>
          </div>
          <span
            className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-lg border ${
              isDark
                ? "bg-emerald-950/70 text-emerald-300 border-emerald-800/80"
                : "bg-emerald-50 text-emerald-700 border-emerald-200/80"
            }`}
          >
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            Active Pipeline
          </span>
        </div>

        <div className="space-y-3 mt-4">
          {sources.map((src) => (
            <div
              key={src.name}
              className={`p-3.5 rounded-xl border transition-colors ${
                isDark
                  ? "bg-slate-800/70 border-slate-750 hover:border-slate-700"
                  : "bg-gray-50/80 border-gray-100 hover:border-gray-200"
              }`}
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-bold ${isDark ? "text-slate-100" : "text-gray-900"}`}>{src.name}</span>
                    <span
                      className={`text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded border ${
                        isDark
                          ? "bg-slate-900 text-slate-300 border-slate-700"
                          : "bg-white text-gray-600 border-gray-200"
                      }`}
                    >
                      {src.badge}
                    </span>
                  </div>
                  <p className={`text-[11px] mt-0.5 ${isDark ? "text-slate-400" : "text-gray-500"}`}>{src.type}</p>
                </div>
                <span
                  className={`text-[11px] font-semibold flex items-center gap-1 ${
                    isDark ? "text-emerald-400" : "text-emerald-600"
                  }`}
                >
                  <ShieldCheck size={13} />
                  {src.status}
                </span>
              </div>

              <div
                className={`mt-2.5 pt-2 border-t flex items-center justify-between text-[11px] ${
                  isDark ? "border-slate-700 text-slate-400" : "border-gray-200/60 text-gray-500"
                }`}
              >
                <span className="flex items-center gap-1">
                  <Clock size={12} className={isDark ? "text-slate-500" : "text-gray-400"} />
                  Last Updated:
                </span>
                <span className={`font-medium font-mono ${isDark ? "text-slate-200" : "text-gray-700"}`}>
                  {src.timestamp ? formatDate(src.timestamp) : <span className={isDark ? "text-slate-500 italic" : "text-gray-400 italic"}>Not yet synced</span>}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div
        className={`mt-6 pt-4 border-t flex items-center justify-between text-[11px] ${
          isDark ? "border-slate-800 text-slate-400" : "border-gray-100 text-gray-500"
        }`}
      >
        <span className="flex items-center gap-1">
          <Activity size={13} className={isDark ? "text-emerald-400" : "text-emerald-600"} />
          Ingestion Parse Accuracy:
        </span>
        <span className={`font-bold font-mono ${isDark ? "text-emerald-400" : "text-emerald-700"}`}>
          {parseRate.toFixed(1)}% Error-Free
        </span>
      </div>
    </div>
  );
}
