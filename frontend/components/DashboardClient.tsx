"use client";
import React from "react";
import CVETable from "@/components/CVETable";
import TopRiskDrivers from "@/components/TopRiskDrivers";
import LastUpdatedPanel from "@/components/LastUpdatedPanel";
import {
  ShieldAlert,
  AlertTriangle,
  Info,
  ShieldCheck,
  Flame,
  Layers,
} from "lucide-react";
import { useTheme } from "./ThemeProvider";

interface DashboardClientProps {
  stats: {
    total_cves?: number;
    critical_count?: number;
    high_count?: number;
    medium_count?: number;
    low_count?: number;
    kev_count?: number;
    parse_rate?: number;
    last_updated?: {
      nvd?: string;
      epss?: string;
      kev?: string;
    };
    risk_drivers?: any;
  };
}

export default function DashboardClient({ stats }: DashboardClientProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  const kpiCards = [
    {
      title: "CVEs Analyzed",
      value: stats.total_cves ?? 0,
      icon: Layers,
      color: isDark ? "text-[#F8FAFC]" : "text-gray-900",
      bg: isDark ? "bg-[#111827] border-[#273449]" : "bg-gray-50 border-gray-200",
      titleColor: isDark ? "text-[#94A3B8]" : "text-gray-500",
      accent: isDark ? "text-slate-300" : "text-gray-700",
    },
    {
      title: "Critical Priority",
      value: stats.critical_count ?? 0,
      icon: ShieldAlert,
      color: isDark ? "text-red-400" : "text-red-700",
      bg: isDark ? "bg-red-950/40 border-red-900/50" : "bg-red-50/60 border-red-200",
      titleColor: isDark ? "text-red-300/80" : "text-gray-500",
      accent: isDark ? "text-red-400" : "text-red-600",
    },
    {
      title: "High Priority",
      value: stats.high_count ?? 0,
      icon: AlertTriangle,
      color: isDark ? "text-orange-400" : "text-orange-700",
      bg: isDark ? "bg-orange-950/40 border-orange-900/50" : "bg-orange-50/60 border-orange-200",
      titleColor: isDark ? "text-orange-300/80" : "text-gray-500",
      accent: isDark ? "text-orange-400" : "text-orange-600",
    },
    {
      title: "Medium Priority",
      value: stats.medium_count ?? 0,
      icon: Info,
      color: isDark ? "text-amber-400" : "text-amber-700",
      bg: isDark ? "bg-amber-950/40 border-amber-900/50" : "bg-amber-50/60 border-amber-200",
      titleColor: isDark ? "text-amber-300/80" : "text-gray-500",
      accent: isDark ? "text-amber-400" : "text-amber-600",
    },
    {
      title: "Low Priority",
      value: stats.low_count ?? 0,
      icon: ShieldCheck,
      color: isDark ? "text-emerald-400" : "text-emerald-700",
      bg: isDark ? "bg-emerald-950/40 border-emerald-900/50" : "bg-emerald-50/60 border-emerald-200",
      titleColor: isDark ? "text-emerald-300/80" : "text-gray-500",
      accent: isDark ? "text-emerald-400" : "text-emerald-600",
    },
    {
      title: "Known Exploited (KEV)",
      value: stats.kev_count ?? 0,
      icon: Flame,
      color: isDark ? "text-purple-400" : "text-purple-700",
      bg: isDark ? "bg-purple-950/40 border-purple-900/50" : "bg-purple-50/60 border-purple-200",
      titleColor: isDark ? "text-purple-300/80" : "text-gray-500",
      accent: isDark ? "text-purple-400" : "text-purple-600",
    },
  ];

  return (
    <div className="space-y-8 w-full transition-colors duration-150">
      {/* Header Banner */}
      <div
        className={`flex flex-col md:flex-row md:items-end justify-between gap-4 pb-4 border-b ${
          isDark ? "border-[#273449]" : "border-gray-200/80"
        }`}
      >
        <div>
          <div
            className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold tracking-wide uppercase mb-2 ${
              isDark
                ? "bg-orange-950/60 border border-orange-800/80 text-[#FB923C]"
                : "bg-orange-50 border border-orange-200 text-[#ED7D24]"
            }`}
          >
            Intelligence Engine &bull; Ingestion Pipeline
          </div>
          <h1
            className={`text-3xl sm:text-4xl font-extrabold tracking-tight ${
              isDark ? "text-[#F8FAFC]" : "text-gray-950"
            }`}
          >
            KEVIDENCE — Vulnerability Intelligence Dashboard
          </h1>
          <p className={`text-sm sm:text-base mt-1 max-w-3xl ${isDark ? "text-[#94A3B8]" : "text-gray-600"}`}>
            Evidence-based prioritization of CVEs using technical, exploitation, and organizational signals.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div
            className={`px-4 py-2 rounded-xl border text-right shadow-2xs ${
              isDark ? "bg-[#111827] border-[#273449]" : "bg-white border-gray-200"
            }`}
          >
            <span className={`text-[11px] block font-medium ${isDark ? "text-[#94A3B8]" : "text-gray-400"}`}>
              Pipeline Reliability
            </span>
            <span
              className={`text-sm font-bold font-mono ${
                isDark ? "text-emerald-400" : "text-emerald-600"
              }`}
            >
              {(stats.parse_rate || 100).toFixed(1)}% Ingestion Fidelity
            </span>
          </div>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        {kpiCards.map((kpi) => {
          const Icon = kpi.icon;
          return (
            <div
              key={kpi.title}
              className={`rounded-2xl p-4 border ${kpi.bg} shadow-2xs transition-all hover:shadow-xs`}
            >
              <div className={`flex items-center justify-between text-xs font-semibold ${kpi.titleColor} mb-2`}>
                <span>{kpi.title}</span>
                <Icon size={16} className={kpi.accent} />
              </div>
              <div className={`text-2xl sm:text-3xl font-extrabold font-mono tracking-tight ${kpi.color}`}>
                {kpi.value.toLocaleString()}
              </div>
            </div>
          );
        })}
      </div>

      {/* Risk Drivers & Feed Panels */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-stretch">
        <TopRiskDrivers drivers={stats.risk_drivers} total={stats.total_cves} theme={theme} />
        <LastUpdatedPanel lastUpdated={stats.last_updated} parseRate={stats.parse_rate} theme={theme} />
      </div>

      {/* CVE Explorer / Table Section */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center justify-between">
          <div>
            <h2 className={`text-xl font-bold tracking-tight ${isDark ? "text-[#F8FAFC]" : "text-gray-900"}`}>
              Prioritized Vulnerabilities
            </h2>
            <p className={`text-xs ${isDark ? "text-[#94A3B8]" : "text-gray-500"}`}>
              Filter and explore scored CVE records with transparent risk rationales.
            </p>
          </div>
        </div>
        <CVETable theme={theme} />
      </div>
    </div>
  );
}
