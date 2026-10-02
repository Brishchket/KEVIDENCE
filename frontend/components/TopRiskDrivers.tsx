"use client";
import React from "react";
import { Flame, ShieldAlert, TrendingUp, Server, Globe } from "lucide-react";
import { useTheme } from "./ThemeProvider";

interface DriverData {
  count: number;
  percent: number;
}

interface TopRiskDriversProps {
  drivers?: {
    kev?: DriverData;
    high_cvss?: DriverData;
    high_epss?: DriverData;
    asset_criticality?: DriverData;
    internet_exposure?: DriverData;
  };
  total?: number;
  theme?: "light" | "dark";
}

export default function TopRiskDrivers({ drivers, total = 0, theme: propTheme }: TopRiskDriversProps) {
  const { theme: contextTheme } = useTheme();
  const theme = propTheme || contextTheme || "light";
  const isDark = theme === "dark";

  const driverItems = [
    {
      key: "kev",
      label: "CISA KEV Catalog (Known Exploited)",
      icon: Flame,
      color: "bg-red-500",
      textColor: isDark ? "text-red-300" : "text-red-700",
      bgLight: isDark ? "bg-red-950/60" : "bg-red-50",
      count: drivers?.kev?.count ?? 0,
      percent: drivers?.kev?.percent ?? 0,
      desc: "Active weaponization observed in wild",
    },
    {
      key: "high_cvss",
      label: "High Technical Severity (CVSS ≥ 7.0)",
      icon: ShieldAlert,
      color: "bg-orange-500",
      textColor: isDark ? "text-orange-300" : "text-orange-700",
      bgLight: isDark ? "bg-orange-950/60" : "bg-orange-50",
      count: drivers?.high_cvss?.count ?? 0,
      percent: drivers?.high_cvss?.percent ?? 0,
      desc: "Significant intrinsic vulnerability severity",
    },
    {
      key: "high_epss",
      label: "Elevated Exploitation Probability (EPSS ≥ 5%)",
      icon: TrendingUp,
      color: "bg-amber-500",
      textColor: isDark ? "text-amber-300" : "text-amber-700",
      bgLight: isDark ? "bg-amber-950/60" : "bg-amber-50",
      count: drivers?.high_epss?.count ?? 0,
      percent: drivers?.high_epss?.percent ?? 0,
      desc: "High predictive likelihood of attack execution",
    },
    {
      key: "internet_exposure",
      label: "Internet Exposure (Network Access Vector)",
      icon: Globe,
      color: "bg-blue-500",
      textColor: isDark ? "text-blue-300" : "text-blue-700",
      bgLight: isDark ? "bg-blue-950/60" : "bg-blue-50",
      count: drivers?.internet_exposure?.count ?? 0,
      percent: drivers?.internet_exposure?.percent ?? 0,
      desc: "Remotely accessible via network perimeter",
    },
    {
      key: "asset_criticality",
      label: "Tier-1 Asset Criticality Relevance",
      icon: Server,
      color: "bg-purple-500",
      textColor: isDark ? "text-purple-300" : "text-purple-700",
      bgLight: isDark ? "bg-purple-950/60" : "bg-purple-50",
      count: drivers?.asset_criticality?.count ?? 0,
      percent: drivers?.asset_criticality?.percent ?? 0,
      desc: "Matches mission-critical organizational infrastructure",
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
          <div>
            <h3 className={`text-base font-bold tracking-tight ${isDark ? "text-white" : "text-gray-900"}`}>
              Top Risk Drivers
            </h3>
            <p className={`text-xs mt-0.5 ${isDark ? "text-slate-400" : "text-gray-500"}`}>
              Why are vulnerabilities being prioritized across the corpus?
            </p>
          </div>
          <span
            className={`text-xs font-semibold px-2.5 py-1 rounded-lg border ${
              isDark
                ? "bg-slate-800 text-slate-300 border-slate-700"
                : "bg-slate-100 text-slate-700 border-slate-200"
            }`}
          >
            {total.toLocaleString()} CVEs Computed
          </span>
        </div>

        <div className="space-y-4 mt-5">
          {driverItems.map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.key} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <div className={`flex items-center gap-2 font-medium ${isDark ? "text-slate-200" : "text-gray-800"}`}>
                    <span className={`p-1 rounded-md ${item.bgLight} ${item.textColor}`}>
                      <Icon size={14} />
                    </span>
                    <span>{item.label}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`font-mono ${isDark ? "text-slate-400" : "text-gray-500"}`}>
                      {item.count.toLocaleString()} CVEs
                    </span>
                    <span className={`font-bold font-mono px-1.5 py-0.5 rounded ${item.bgLight} ${item.textColor}`}>
                      {item.percent.toFixed(1)}%
                    </span>
                  </div>
                </div>

                {/* Progress bar */}
                <div className={`w-full rounded-full h-2 overflow-hidden ${isDark ? "bg-slate-800" : "bg-gray-100"}`}>
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${item.color}`}
                    style={{ width: `${Math.max(item.percent, item.count > 0 ? 2 : 0)}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div
        className={`mt-6 pt-4 border-t flex items-center justify-between text-[11px] ${
          isDark ? "border-slate-800 text-slate-400" : "border-gray-100 text-gray-500"
        }`}
      >
        <span>Deterministic signal correlation</span>
        <span>Weights: KEV (40%) &bull; CVSS (30%) &bull; EPSS (30%)</span>
      </div>
    </div>
  );
}
