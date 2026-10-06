"use client";
import React, { useEffect, useState, useTransition } from "react";
import Link from "next/link";
import { fetcher } from "@/lib/api";
import { PriorityBadge } from "./Badges";
import DownloadReportButton from "./DownloadReportButton";
import { Search, Filter, RotateCcw, ChevronRight, ShieldAlert, Check, ArrowUpDown, ChevronLeft } from "lucide-react";
import { INDUSTRIES } from "@/lib/constants";

export type CVEItem = {
  cve_id: string;
  description: string;
  priority_label: string;
  priority_score: number;
  cvss_base_score?: number | null;
  severity?: string | null;
  cvss_vector?: string | null;
  attack_vector?: string | null;
  epss_score?: number | null;
  in_kev: boolean;
  reasons?: string[];
  vendors?: string[];
  products?: string[];
};

export function generateWhyString(cve: CVEItem): string {
  const parts: string[] = [];

  // 1. KEV Signal
  if (cve.in_kev) {
    parts.push("KEV Listed");
  }

  // 2. Technical Severity
  if (cve.cvss_base_score !== undefined && cve.cvss_base_score !== null) {
    if (cve.cvss_base_score >= 9.0) {
      parts.push(`Critical Severity (${cve.cvss_base_score.toFixed(1)})`);
    } else if (cve.cvss_base_score >= 7.0) {
      parts.push(`High Severity (${cve.cvss_base_score.toFixed(1)})`);
    } else if (cve.cvss_base_score >= 4.0) {
      parts.push(`Moderate Severity (${cve.cvss_base_score.toFixed(1)})`);
    } else {
      parts.push(`Low Severity (${cve.cvss_base_score.toFixed(1)})`);
    }
  } else if (cve.severity) {
    parts.push(`${cve.severity} Severity`);
  }

  // 3. EPSS Exploitation
  const epss = Number(cve.epss_score || 0);
  if (epss >= 0.5) {
    parts.push(`High Exploitation (${(epss * 100).toFixed(0)}%)`);
  } else if (epss >= 0.05) {
    parts.push(`Active Exploit Signal (${(epss * 100).toFixed(1)}%)`);
  } else if (epss > 0.01) {
    parts.push(`EPSS (${(epss * 100).toFixed(1)}%)`);
  }

  // 4. Exposure Vector
  const vector = cve.cvss_vector || "";
  const isNetwork = vector.includes("AV:N") || cve.attack_vector === "NETWORK";
  if (isNetwork) {
    parts.push("Network Exposure");
  } else if (vector.includes("AV:A")) {
    parts.push("Adjacent Network");
  } else if (vector.includes("AV:L")) {
    parts.push("Local Vector");
  }

  // Fallback to reasons from backend if available
  if (parts.length === 0) {
    if (cve.reasons && cve.reasons.length > 0) {
      return cve.reasons.join(" + ");
    }
    return `${cve.priority_label} Priority Signal`;
  }

  return parts.join(" + ");
}

import { useTheme } from "./ThemeProvider";
import type { LiveEvent } from "@/lib/useLiveFeed";

interface CVETableProps {
  theme?: "light" | "dark";
  /** Live events from the SSE feed — used to highlight changed rows */
  liveEvents?: LiveEvent[];
  /** Called when the user dismisses the pending pill */
  onClearPending?: () => void;
}

export default function CVETable({ theme: propTheme, liveEvents = [], onClearPending }: CVETableProps) {
  const { theme: contextTheme } = useTheme();
  const theme = propTheme || contextTheme || "light";
  const isDark = theme === "dark";
  const [cves, setCves] = useState<CVEItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [isPending, startTransition] = useTransition();

  // Track CVE IDs that were recently updated — cleared after animation
  const [highlightedIds, setHighlightedIds] = useState<Set<string>>(new Set());

  // When liveEvents changes, highlight affected rows already visible
  useEffect(() => {
    if (!liveEvents || liveEvents.length === 0) return;
    const newIds = liveEvents
      .filter((e) => e.cve_id)
      .map((e) => e.cve_id);
    if (newIds.length === 0) return;
    setHighlightedIds((prev) => {
      const next = new Set(prev);
      newIds.forEach((id) => next.add(id));
      return next;
    });
    // Fade out highlight after 4 seconds
    const t = setTimeout(() => {
      setHighlightedIds((prev) => {
        const next = new Set(prev);
        newIds.forEach((id) => next.delete(id));
        return next;
      });
    }, 4_000);
    return () => clearTimeout(t);
  }, [liveEvents]);

  // Filter States
  const [searchInput, setSearchInput] = useState("");
  const [appliedSearch, setAppliedSearch] = useState("");
  const [priorityFilter, setPriorityFilter] = useState("");
  const [kevFilter, setKevFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [industryFilter, setIndustryFilter] = useState("");

  // Pagination & Sorting
  const [page, setPage] = useState(1);
  const limit = 15;
  const [sortBy, setSortBy] = useState("priority_score");
  const [sortOrder, setSortOrder] = useState<"desc" | "asc">("desc");

  const loadData = (resetPage = false) => {
    setLoading(true);
    const currentPage = resetPage ? 1 : page;
    if (resetPage) setPage(1);

    const params = new URLSearchParams();
    params.set("limit", limit.toString());
    params.set("offset", ((currentPage - 1) * limit).toString());
    params.set("sort", sortBy);
    params.set("order", sortOrder);

    if (appliedSearch.trim()) params.set("search", appliedSearch.trim());
    if (priorityFilter) params.set("priority", priorityFilter);
    if (kevFilter === "yes") params.set("in_kev", "true");
    if (kevFilter === "no") params.set("in_kev", "false");
    if (severityFilter) params.set("severity", severityFilter);

    fetcher(`/cves?${params.toString()}`)
      .then((res) => {
        setCves(res.items || []);
        setTotal(res.total || 0);
        setLoading(false);
      })
      .catch(() => {
        setCves([]);
        setTotal(0);
        setLoading(false);
      });
  };

  useEffect(() => {
    loadData();
  }, [page, appliedSearch, priorityFilter, kevFilter, severityFilter, sortBy, sortOrder]);

  const handleApply = (e: React.FormEvent) => {
    e.preventDefault();
    setAppliedSearch(searchInput);
    setPage(1);
  };

  const handleReset = () => {
    setSearchInput("");
    setAppliedSearch("");
    setPriorityFilter("");
    setKevFilter("");
    setSeverityFilter("");
    setIndustryFilter("");
    setPage(1);
  };

  const totalPages = Math.max(1, Math.ceil(total / limit));

  return (
    <div id="explorer" className="space-y-4">
      {/* Search & Filter Bar */}
      <div
        className={`rounded-2xl border p-5 transition-colors ${
          isDark
            ? "bg-slate-900 border-slate-800 shadow-md text-slate-100"
            : "bg-white border-gray-200/90 shadow-2xs text-gray-900"
        }`}
      >
        <form onSubmit={handleApply} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center">
            {/* Search Input */}
            <div className="md:col-span-4 relative">
              <Search
                size={16}
                className={`absolute left-3.5 top-1/2 -translate-y-1/2 ${isDark ? "text-slate-500" : "text-gray-400"}`}
              />
              <input
                type="text"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder="Search CVE ID, vendor, or product..."
                className={`w-full pl-9 pr-4 py-2 text-xs sm:text-sm rounded-xl focus:ring-2 focus:ring-[#ED7D24]/20 focus:border-[#ED7D24] transition-all ${
                  isDark
                    ? "bg-slate-800 border-slate-700 text-slate-100 placeholder-slate-500 focus:bg-slate-900"
                    : "bg-gray-50 border-gray-200 text-gray-900 placeholder-gray-400 focus:bg-white"
                }`}
              />
            </div>

            {/* Priority Filter */}
            <div className="md:col-span-2">
              <select
                value={priorityFilter}
                onChange={(e) => {
                  setPriorityFilter(e.target.value);
                  setPage(1);
                }}
                className={`w-full px-3 py-2 text-xs sm:text-sm rounded-xl focus:ring-2 focus:ring-[#ED7D24]/20 focus:border-[#ED7D24] font-medium ${
                  isDark
                    ? "bg-slate-800 border-slate-700 text-slate-200 focus:bg-slate-900"
                    : "bg-gray-50 border-gray-200 text-gray-700 focus:bg-white"
                }`}
              >
                <option value="">All Priorities</option>
                <option value="CRITICAL">Critical Priority</option>
                <option value="HIGH">High Priority</option>
                <option value="MEDIUM">Medium Priority</option>
                <option value="LOW">Low Priority</option>
              </select>
            </div>

            {/* KEV Filter */}
            <div className="md:col-span-2">
              <select
                value={kevFilter}
                onChange={(e) => {
                  setKevFilter(e.target.value);
                  setPage(1);
                }}
                className={`w-full px-3 py-2 text-xs sm:text-sm rounded-xl focus:ring-2 focus:ring-[#ED7D24]/20 focus:border-[#ED7D24] font-medium ${
                  isDark
                    ? "bg-slate-800 border-slate-700 text-slate-200 focus:bg-slate-900"
                    : "bg-gray-50 border-gray-200 text-gray-700 focus:bg-white"
                }`}
              >
                <option value="">All KEV Status</option>
                <option value="yes">Known Exploited (KEV)</option>
                <option value="no">Not Listed in KEV</option>
              </select>
            </div>

            {/* Severity Filter */}
            <div className="md:col-span-2">
              <select
                value={severityFilter}
                onChange={(e) => {
                  setSeverityFilter(e.target.value);
                  setPage(1);
                }}
                className={`w-full px-3 py-2 text-xs sm:text-sm rounded-xl focus:ring-2 focus:ring-[#ED7D24]/20 focus:border-[#ED7D24] font-medium ${
                  isDark
                    ? "bg-slate-800 border-slate-700 text-slate-200 focus:bg-slate-900"
                    : "bg-gray-50 border-gray-200 text-gray-700 focus:bg-white"
                }`}
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">CVSS Critical (9.0+)</option>
                <option value="HIGH">CVSS High (7.0 - 8.9)</option>
                <option value="MEDIUM">CVSS Medium (4.0 - 6.9)</option>
                <option value="LOW">CVSS Low (0.1 - 3.9)</option>
              </select>
            </div>

            {/* Industry Filter (Contextual) */}
            <div className="md:col-span-2">
              <select
                value={industryFilter}
                onChange={(e) => {
                  setIndustryFilter(e.target.value);
                }}
                className={`w-full px-3 py-2 text-xs sm:text-sm rounded-xl focus:ring-2 focus:ring-[#ED7D24]/20 focus:border-[#ED7D24] font-medium ${
                  isDark
                    ? "bg-slate-800 border-slate-700 text-slate-200 focus:bg-slate-900"
                    : "bg-gray-50 border-gray-200 text-gray-700 focus:bg-white"
                }`}
              >
                <option value="">Organization Scope</option>
                {INDUSTRIES.map((ind) => (
                  <option key={ind} value={ind}>
                    {ind}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div
            className={`flex items-center justify-between pt-2 border-t text-xs ${
              isDark ? "border-slate-800" : "border-gray-100"
            }`}
          >
            <div className={`${isDark ? "text-slate-400" : "text-gray-500"} font-medium`}>
              Showing <span className={`font-bold ${isDark ? "text-slate-100" : "text-gray-900"}`}>{cves.length}</span> of{" "}
              <span className={`font-bold ${isDark ? "text-slate-100" : "text-gray-900"}`}>
                {total.toLocaleString()}
              </span>{" "}
              vulnerabilities
            </div>
            <div className="flex items-center gap-2">
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg bg-[#ED7D24] hover:bg-[#D96B16] text-white font-medium text-xs transition-colors shadow-2xs"
              >
                Apply Filters
              </button>
              <button
                type="button"
                onClick={handleReset}
                className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg font-medium text-xs transition-colors ${
                  isDark
                    ? "bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
                    : "bg-gray-100 hover:bg-gray-200 text-gray-700"
                }`}
              >
                <RotateCcw size={12} />
                Reset
              </button>
            </div>
          </div>
        </form>
      </div>

      {/* Main Table Container */}
      <div
        className={`rounded-2xl border shadow-2xs overflow-hidden w-full transition-colors ${
          isDark ? "bg-slate-900 border-slate-800" : "bg-white border-gray-200/90"
        }`}
      >
        <div className="overflow-x-auto w-full">
          <table className="w-full text-left text-sm border-collapse">
            <thead
              className={`border-b text-xs font-bold uppercase tracking-wider ${
                isDark
                  ? "bg-slate-950/90 border-slate-800 text-slate-400"
                  : "bg-gray-50/90 border-gray-200 text-gray-600"
              }`}
            >
              <tr>
                <th className="px-5 py-3.5 whitespace-nowrap">CVE</th>
                <th className="px-5 py-3.5 whitespace-nowrap">Priority</th>
                <th className="px-5 py-3.5 whitespace-nowrap">
                  <button
                    onClick={() => {
                      setSortBy("priority_score");
                      setSortOrder(sortOrder === "desc" ? "asc" : "desc");
                    }}
                    className={`inline-flex items-center gap-1 ${
                      isDark ? "hover:text-slate-100" : "hover:text-gray-900"
                    }`}
                  >
                    Score
                    <ArrowUpDown size={12} />
                  </button>
                </th>
                <th className="px-5 py-3.5 whitespace-nowrap">KEV</th>
                <th className="px-5 py-3.5">Why? (Deterministic Risk Drivers)</th>
                <th className="px-5 py-3.5 text-right whitespace-nowrap">Actions</th>
              </tr>
            </thead>
            <tbody className={`divide-y ${isDark ? "divide-slate-800 text-slate-200" : "divide-gray-100 text-gray-700"}`}>
              {loading ? (
                <tr>
                  <td colSpan={6} className={`px-6 py-12 text-center ${isDark ? "text-slate-400" : "text-gray-500"}`}>
                    <div className="flex flex-col items-center justify-center gap-2">
                      <div className="w-6 h-6 border-2 border-[#ED7D24] border-t-transparent rounded-full animate-spin" />
                      <span className="text-xs font-medium">Loading CVE intelligence...</span>
                    </div>
                  </td>
                </tr>
              ) : cves.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center">
                    <p className={`font-semibold ${isDark ? "text-slate-200" : "text-gray-700"}`}>
                      No matching vulnerabilities found.
                    </p>
                    <p className={`text-xs mt-1 ${isDark ? "text-slate-500" : "text-gray-400"}`}>
                      Try resetting your search query or filters.
                    </p>
                  </td>
                </tr>
              ) : (
                cves.map((cve) => {
                  const whyText = generateWhyString(cve);
                  const isHighlighted = highlightedIds.has(cve.cve_id);
                  return (
                    <tr
                      key={cve.cve_id}
                      className={`transition-colors group ${
                        isHighlighted
                          ? isDark
                            ? "bg-emerald-950/30 border-l-2 border-l-emerald-500"
                            : "bg-emerald-50/60 border-l-2 border-l-emerald-500"
                          : isDark
                          ? "hover:bg-slate-800/60"
                          : "hover:bg-slate-50/80"
                      }`}
                    >
                      {/* CVE ID */}
                      <td className="px-5 py-4 font-mono font-bold whitespace-nowrap">
                        <Link
                          href={`/cve/${cve.cve_id}`}
                          className={`inline-flex items-center gap-1 ${
                            isDark
                              ? "text-blue-400 hover:text-blue-300 hover:underline"
                              : "text-blue-600 hover:text-blue-800 hover:underline"
                          }`}
                        >
                          {cve.cve_id}
                        </Link>
                      </td>

                      {/* Priority */}
                      <td className="px-5 py-4 whitespace-nowrap">
                        <PriorityBadge label={cve.priority_label} size="sm" />
                      </td>

                      {/* Score */}
                      <td className="px-5 py-4 whitespace-nowrap">
                        <div className="flex items-center gap-2 font-mono">
                          <span className={`font-bold text-sm ${isDark ? "text-slate-100" : "text-gray-900"}`}>
                            {cve.priority_score.toFixed(3)}
                          </span>
                          <div
                            className={`w-12 rounded-full h-1.5 overflow-hidden hidden sm:block ${
                              isDark ? "bg-slate-800" : "bg-gray-100"
                            }`}
                          >
                            <div
                              className="h-full bg-[#ED7D24] rounded-full"
                              style={{ width: `${Math.min(100, cve.priority_score * 100)}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* KEV Flag */}
                      <td className="px-5 py-4 whitespace-nowrap">
                        {cve.in_kev ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold bg-red-100 text-red-800 border border-red-200">
                            <ShieldAlert size={12} className="text-red-600" />
                            YES
                          </span>
                        ) : (
                          <span className={`text-xs font-medium ${isDark ? "text-slate-500" : "text-gray-400"}`}>
                            NO
                          </span>
                        )}
                      </td>

                      {/* Why? Column */}
                      <td className="px-5 py-4">
                        <div
                          className={`text-xs font-medium leading-relaxed max-w-xl ${
                            isDark ? "text-slate-300" : "text-gray-800"
                          }`}
                        >
                          {whyText}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="px-5 py-4 text-right whitespace-nowrap">
                        <div className="inline-flex items-center gap-1.5">
                          <DownloadReportButton cveId={cve.cve_id} variant="icon" />
                          <Link
                            href={`/cve/${cve.cve_id}`}
                            className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-bold transition-all shadow-2xs ${
                              isDark
                                ? "bg-slate-800 text-slate-200 hover:bg-[#ED7D24] hover:text-white border border-slate-700"
                                : "text-gray-700 bg-gray-100 hover:bg-[#ED7D24] hover:text-white"
                            }`}
                          >
                            View Details
                            <ChevronRight size={13} />
                          </Link>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div
          className={`px-5 py-4 border-t flex flex-col sm:flex-row items-center justify-between gap-3 text-xs ${
            isDark ? "border-slate-800 bg-slate-950/60" : "border-gray-200/80 bg-gray-50/50"
          }`}
        >
          <span className={`font-medium ${isDark ? "text-slate-400" : "text-gray-500"}`}>
            Page <span className={`font-bold ${isDark ? "text-slate-100" : "text-gray-900"}`}>{page}</span> of{" "}
            <span className={`font-bold ${isDark ? "text-slate-100" : "text-gray-900"}`}>{totalPages}</span>
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1 || loading}
              className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors ${
                isDark
                  ? "border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700"
                  : "border-gray-200 bg-white text-gray-700 hover:bg-gray-50"
              }`}
            >
              <ChevronLeft size={14} />
              Previous
            </button>
            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages || loading}
              className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border font-medium disabled:opacity-40 disabled:cursor-not-allowed transition-colors ${
                isDark
                  ? "border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700"
                  : "border-gray-200 bg-white text-gray-700 hover:bg-gray-50"
              }`}
            >
              Next
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
