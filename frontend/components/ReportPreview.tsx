"use client";
/**
 * ReportPreview.tsx — Interactive on-page preview of the structured 6-section vulnerability report.
 *
 * Allows security analysts and managers to preview all six report sections,
 * score breakdown table, version constraints, and verification metrics directly
 * on the CVE detail page before or alongside downloading the formal PDF.
 */

import React, { useEffect, useState } from "react";
import {
  FileText,
  ShieldCheck,
  ChevronDown,
  ChevronUp,
  Download,
  AlertTriangle,
  Info,
  CheckCircle2,
  Clock,
  Layers,
  Wrench,
  HelpCircle,
} from "lucide-react";
import { API_BASE } from "@/lib/api";
import { useTheme } from "./ThemeProvider";
import DownloadReportButton from "./DownloadReportButton";

interface ReportPreviewProps {
  cveId: string;
}

export default function ReportPreview({ cveId }: ReportPreviewProps) {
  const { theme } = useTheme();
  const isDark = theme === "dark";

  const [isOpen, setIsOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && !report && !loading) {
      setLoading(true);
      setError(null);
      fetch(`${API_BASE}/cves/${cveId}/report`)
        .then((res) => {
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          return res.json();
        })
        .then((data) => {
          setReport(data);
          setLoading(false);
        })
        .catch((err) => {
          console.error("Report preview fetch error:", err);
          setError("Failed to load structured report preview.");
          setLoading(false);
        });
    }
  }, [isOpen, report, loading, cveId]);

  return (
    <div
      className={`rounded-2xl border transition-colors overflow-hidden ${
        isDark ? "bg-[#111827] border-[#273449]" : "bg-white border-gray-200/90 shadow-2xs"
      }`}
    >
      {/* Header bar / accordion toggle */}
      <div className="p-5 flex flex-wrap items-center justify-between gap-4">
        <button
          type="button"
          onClick={() => setIsOpen((prev) => !prev)}
          className="flex items-center gap-3 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] rounded-lg p-1"
        >
          <div
            className={`p-2.5 rounded-xl ${
              isDark ? "bg-orange-950/60 text-[#FB923C]" : "bg-orange-50 text-[#ED7D24]"
            }`}
          >
            <FileText size={20} />
          </div>
          <div>
            <h3 className={`text-base sm:text-lg font-bold ${isDark ? "text-[#F8FAFC]" : "text-gray-900"}`}>
              Structured Vulnerability Report Preview
            </h3>
            <p className={`text-xs ${isDark ? "text-[#94A3B8]" : "text-gray-500"}`}>
              Explore the evidence-grounded 6 questions (WHY, WHAT, WHERE, HOW, RESOLUTION, ORIGIN).
            </p>
          </div>
          {isOpen ? (
            <ChevronUp size={18} className={isDark ? "text-slate-400" : "text-gray-400"} />
          ) : (
            <ChevronDown size={18} className={isDark ? "text-slate-400" : "text-gray-400"} />
          )}
        </button>

        <div className="flex items-center gap-3">
          <DownloadReportButton cveId={cveId} variant="button" />
        </div>
      </div>

      {/* Expandable Preview Body */}
      {isOpen && (
        <div className={`p-6 border-t ${isDark ? "border-[#273449]" : "border-gray-100"} space-y-6`}>
          {loading ? (
            <div className="py-12 flex flex-col items-center justify-center gap-3">
              <div className="w-8 h-8 border-3 border-[#ED7D24] border-t-transparent rounded-full animate-spin" />
              <span className={`text-xs font-semibold ${isDark ? "text-slate-400" : "text-gray-500"}`}>
                Assembling evidence-grounded report sections…
              </span>
            </div>
          ) : error ? (
            <div className="p-4 rounded-xl bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-900 text-red-700 dark:text-red-300 text-xs">
              {error}
            </div>
          ) : report ? (
            <div className="space-y-6">
              {/* 1. Executive Summary */}
              <div
                className={`p-4 rounded-xl border ${
                  isDark ? "bg-[#172033] border-[#273449]" : "bg-slate-50 border-slate-200"
                }`}
              >
                <div className="flex items-center gap-2 mb-2">
                  <ShieldCheck size={16} className="text-[#ED7D24]" />
                  <span className="text-xs font-bold uppercase tracking-wider text-[#ED7D24]">
                    1. Executive Summary (BLUF)
                  </span>
                </div>
                <p className={`text-sm leading-relaxed ${isDark ? "text-slate-200" : "text-gray-800"}`}>
                  {report.executive_summary}
                </p>
              </div>

              {/* 2. WHAT */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-slate-400 flex items-center gap-1.5">
                  <HelpCircle size={14} className="text-blue-500" />
                  2. What is the Vulnerability?
                </h4>
                <p className={`text-xs sm:text-sm leading-relaxed ${isDark ? "text-slate-300" : "text-gray-700"}`}>
                  {report.sections?.what}
                </p>
              </div>

              {/* 3. WHY */}
              <div className="space-y-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-slate-400 flex items-center gap-1.5">
                  <AlertTriangle size={14} className="text-amber-500" />
                  3. Why is this Prioritised?
                </h4>
                <p className={`text-xs sm:text-sm leading-relaxed ${isDark ? "text-slate-300" : "text-gray-700"}`}>
                  {report.sections?.why}
                </p>

                {/* Score Breakdown Table */}
                {report.score_breakdown && (
                  <div className="overflow-x-auto rounded-xl border border-gray-200 dark:border-[#273449]">
                    <table className="w-full text-left text-xs">
                      <thead
                        className={`${
                          isDark ? "bg-slate-900 text-slate-300" : "bg-gray-100 text-gray-700"
                        } font-bold uppercase text-[10px]`}
                      >
                        <tr>
                          <th className="px-4 py-2.5">Component</th>
                          <th className="px-4 py-2.5">Raw Value</th>
                          <th className="px-4 py-2.5">Weight</th>
                          <th className="px-4 py-2.5">Contribution</th>
                          <th className="px-4 py-2.5">Feed Source</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-200 dark:divide-[#273449]">
                        {report.score_breakdown.map((row: any, i: number) => (
                          <tr key={i} className={isDark ? "hover:bg-slate-800/40" : "hover:bg-gray-50"}>
                            <td className="px-4 py-2 font-semibold">{row.component}</td>
                            <td className="px-4 py-2 font-mono">{row.raw_value}</td>
                            <td className="px-4 py-2 font-mono">{row.weight}</td>
                            <td className="px-4 py-2 font-mono font-bold text-[#ED7D24]">{row.contribution}</td>
                            <td className="px-4 py-2 font-mono text-[10px] text-gray-500">{row.source}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* 4. WHERE */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-slate-400 flex items-center gap-1.5">
                  <Layers size={14} className="text-purple-500" />
                  4. Where is it Affected? (Asset Scope)
                </h4>
                <p className={`text-xs sm:text-sm leading-relaxed ${isDark ? "text-slate-300" : "text-gray-700"}`}>
                  {report.sections?.where}
                </p>
              </div>

              {/* 5. HOW */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-slate-400 flex items-center gap-1.5">
                  <Info size={14} className="text-red-500" />
                  5. How is it Exploited? (Threat Intel)
                </h4>
                <p className={`text-xs sm:text-sm leading-relaxed ${isDark ? "text-slate-300" : "text-gray-700"}`}>
                  {report.sections?.how}
                </p>
              </div>

              {/* 6. RESOLUTION */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-slate-400 flex items-center gap-1.5">
                  <Wrench size={14} className="text-emerald-500" />
                  6. Resolution Plan (Mitigation & Patches)
                </h4>
                <p className={`text-xs sm:text-sm leading-relaxed ${isDark ? "text-slate-300" : "text-gray-700"}`}>
                  {report.sections?.resolution}
                </p>
              </div>

              {/* 7. ORIGIN */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-slate-400 flex items-center gap-1.5">
                  <Clock size={14} className="text-teal-500" />
                  7. Origin & Root Cause (MITRE CWE & Timeline)
                </h4>
                <p className={`text-xs sm:text-sm leading-relaxed ${isDark ? "text-slate-300" : "text-gray-700"}`}>
                  {report.sections?.origin}
                </p>
              </div>

              {/* 8. Verification Appendix */}
              <div
                className={`p-4 rounded-xl border text-xs space-y-2 ${
                  isDark ? "bg-slate-900 border-[#273449] text-slate-300" : "bg-gray-50 border-gray-200 text-gray-600"
                }`}
              >
                <div className="flex items-center justify-between font-bold">
                  <span>Evidence & Verification Grounding</span>
                  <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                    <CheckCircle2 size={13} />
                    Faithfulness: {((report.verification?.faithfulness_score || 1) * 100).toFixed(1)}% ({report.verification?.confidence || "HIGH"})
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
                  <div>Verified Claims: {report.verification?.verified_sentences_count ?? 0}</div>
                  <div>Dropped Claims: {report.verification?.dropped_sentences_count ?? 0}</div>
                  <div>Provider: {report.provider}</div>
                  <div>Prompt: {report.prompt_version}</div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
      )}
    </div>
  );
}
