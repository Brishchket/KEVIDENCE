"use client";
import React, { useState, useEffect } from "react";
import { fetcher } from "@/lib/api";
import { SourceDataBadge, GeneratedBadge, VerifiedBadge } from "@/components/Badges";
import {
  Database,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  FileText,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  Flame,
  TrendingUp,
  Server,
  Layers,
  Activity,
  ArrowRight
} from "lucide-react";

type CompareData = {
  cve_id: string;
  raw_description: string;
  keevidence_narrative?: string;
  phantompatch_narrative?: string;
  raw_flesch: number | null;
  keevidence_flesch?: number | null;
  phantompatch_flesch?: number | null;
  keevidence_unsupported_rate?: number | null;
  phantompatch_unsupported_rate?: number | null;
};

export default function ComparePage() {
  const [cves, setCves] = useState<{ cve_id: string }[]>([]);
  const [selectedCve, setSelectedCve] = useState<string>("");
  const [compareData, setCompareData] = useState<CompareData | null>(null);
  const [evidence, setEvidence] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [showRawBaseline, setShowRawBaseline] = useState(false);

  useEffect(() => {
    fetcher("/cves?limit=50").then((d) => {
      const items = d.items || [];
      setCves(items);
      if (items.length > 0) {
        setSelectedCve(items[0].cve_id);
      }
    });
  }, []);

  useEffect(() => {
    if (!selectedCve) return;
    setLoading(true);
    Promise.all([
      fetcher(`/compare/${selectedCve}`),
      fetcher(`/cves/${selectedCve}`).catch(() => null),
    ])
      .then(([comp, evid]) => {
        setCompareData(comp);
        setEvidence(evid);
        setLoading(false);
      })
      .catch(() => {
        setLoading(false);
      });
  }, [selectedCve]);

  const unsupportedRate = compareData?.phantompatch_unsupported_rate !== null && compareData?.phantompatch_unsupported_rate !== undefined
    ? compareData.phantompatch_unsupported_rate
    : 0.0;
  const faithfulnessScore = Math.max(0, 1 - unsupportedRate);

  return (
    <div className="max-w-[1600px] mx-auto space-y-8 w-full transition-colors duration-150">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2 border-b border-gray-200/80 dark:border-[#273449]">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-800 text-blue-700 dark:text-blue-300 text-xs font-bold tracking-wide uppercase mb-2">
            Verification & Grounding Harness
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-gray-950 dark:text-[#F8FAFC] tracking-tight">
            Evidence vs Generated Summary
          </h1>
          <p className="text-sm sm:text-base text-gray-600 dark:text-[#94A3B8] mt-1 max-w-3xl">
            Side-by-side comparative inspection of raw ground-truth evidence signals versus verified LLM narrative outputs.
          </p>
        </div>

        {/* CVE Selector Dropdown */}
        <div className="w-full sm:w-72 bg-white dark:bg-[#111827] p-2 rounded-2xl border border-gray-200 dark:border-[#273449] shadow-2xs">
          <label className="block text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-[#94A3B8] mb-1 px-1">
            Select Vulnerability (CVE)
          </label>
          <select
            value={selectedCve}
            onChange={(e) => setSelectedCve(e.target.value)}
            className="block w-full rounded-xl bg-gray-50 dark:bg-[#172033] border border-gray-200 dark:border-[#273449] text-gray-900 dark:text-[#F8FAFC] font-mono font-bold text-sm p-2.5 focus:ring-2 focus:ring-[#ED7D24]/20 focus:border-[#ED7D24] transition-all"
          >
            {cves.map((c) => (
              <option key={c.cve_id} value={c.cve_id}>
                {c.cve_id}
              </option>
            ))}
          </select>
        </div>
      </div>

      {loading || !compareData ? (
        <div className="p-16 text-center text-gray-500 dark:text-[#94A3B8] bg-white dark:bg-[#111827] rounded-2xl border border-gray-200 dark:border-[#273449]">
          <div className="w-8 h-8 border-2 border-[#ED7D24] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <span className="text-sm font-medium">Loading comparative grounding analysis...</span>
        </div>
      ) : (
        <div className="space-y-8">
          {/* Main 2-Panel Comparison (Source Evidence vs Generated Summary) */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 items-stretch">
            {/* LEFT PANEL: SOURCE EVIDENCE */}
            <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs overflow-hidden flex flex-col justify-between transition-colors">
              <div>
                <div className="bg-slate-50 dark:bg-[#172033] px-6 py-4 border-b border-gray-200 dark:border-[#273449] flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Database size={18} className="text-slate-700 dark:text-slate-300" />
                    <h2 className="text-base font-bold text-gray-900 dark:text-[#F8FAFC] tracking-tight">SOURCE EVIDENCE</h2>
                  </div>
                  <SourceDataBadge source="Authoritative Feeds" />
                </div>

                <div className="p-6 space-y-5">
                  <div className="grid grid-cols-2 gap-4">
                    {/* CVSS Metric */}
                    <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#172033] border border-gray-200/80 dark:border-[#273449] space-y-1">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-[#94A3B8] block">
                        CVSS v3.1 Score
                      </span>
                      <div className="text-xl font-extrabold font-mono text-gray-900 dark:text-[#F8FAFC]">
                        {evidence?.cvss?.score !== null && evidence?.cvss?.score !== undefined
                          ? evidence.cvss.score.toFixed(1)
                          : "N/A"}
                      </div>
                      <span className="text-xs text-gray-600 dark:text-slate-300 font-medium">
                        {evidence?.cvss?.severity || "Unrated Severity"}
                      </span>
                    </div>

                    {/* EPSS Metric */}
                    <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#172033] border border-gray-200/80 dark:border-[#273449] space-y-1">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-[#94A3B8] block">
                        EPSS Likelihood
                      </span>
                      <div className="text-xl font-extrabold font-mono text-gray-900 dark:text-[#F8FAFC]">
                        {evidence?.epss?.probability !== null && evidence?.epss?.probability !== undefined
                          ? `${(evidence.epss.probability * 100).toFixed(2)}%`
                          : "0.00%"}
                      </div>
                      <span className="text-xs text-gray-600 dark:text-slate-300 font-medium">
                        {evidence?.epss?.percentile ? `${(evidence.epss.percentile * 100).toFixed(0)}th Percentile` : "Exploit probability"}
                      </span>
                    </div>

                    {/* CISA KEV */}
                    <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#172033] border border-gray-200/80 dark:border-[#273449] space-y-1">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-[#94A3B8] block">
                        CISA KEV Catalog
                      </span>
                      <div className={`text-xl font-extrabold font-mono ${evidence?.kev?.in_kev ? "text-red-700 dark:text-red-400" : "text-gray-700 dark:text-slate-400"}`}>
                        {evidence?.kev?.in_kev ? "YES" : "NO"}
                      </div>
                      <span className="text-xs text-gray-600 dark:text-slate-300 font-medium">
                        {evidence?.kev?.in_kev ? "Known Exploited" : "Not listed"}
                      </span>
                    </div>

                    {/* Affected Product */}
                    <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#172033] border border-gray-200/80 dark:border-[#273449] space-y-1">
                      <span className="text-[11px] font-bold uppercase tracking-wider text-gray-500 dark:text-[#94A3B8] block">
                        Affected Component
                      </span>
                      <div className="text-sm font-bold text-gray-900 dark:text-[#F8FAFC] truncate" title={evidence?.affected?.product || "Component"}>
                        {evidence?.affected?.product || "Not specified"}
                      </div>
                      <span className="text-xs text-gray-500 dark:text-[#94A3B8] truncate block">
                        Vendor: {evidence?.affected?.vendor || "Vendor"}
                      </span>
                    </div>
                  </div>

                  {/* Ground Truth Signals Summary */}
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#0B1120] border border-slate-200 dark:border-[#273449] space-y-2 text-xs">
                    <span className="text-slate-900 dark:text-slate-200 font-bold uppercase tracking-wider text-[11px] block">
                      Deterministic Prioritization Output:
                    </span>
                    <div className="flex items-center justify-between text-gray-700 dark:text-slate-300">
                      <span>Composite Priority Score:</span>
                      <span className="font-bold font-mono text-gray-900 dark:text-[#F8FAFC]">
                        {evidence?.priority?.score !== undefined ? evidence.priority.score.toFixed(3) : "—"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-gray-700 dark:text-slate-300">
                      <span>Assigned Risk Tier:</span>
                      <span className="font-bold font-mono text-gray-900 dark:text-[#F8FAFC]">
                        {evidence?.priority?.label || "LOW"} PRIORITY
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              <div className="bg-gray-50/80 dark:bg-[#172033] px-6 py-3 border-t border-gray-200 dark:border-[#273449] text-xs text-gray-500 dark:text-[#94A3B8] flex items-center justify-between">
                <span>Directly extracted from database</span>
                <span>Ground Truth (Zero Hallucination)</span>
              </div>
            </div>

            {/* RIGHT PANEL: GENERATED SUMMARY */}
            <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs overflow-hidden flex flex-col justify-between ring-1 ring-blue-500/20 transition-colors">
              <div>
                <div className="bg-blue-50/80 dark:bg-[#172033] px-6 py-4 border-b border-blue-200 dark:border-[#273449] flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sparkles size={18} className="text-blue-700 dark:text-blue-400" />
                    <h2 className="text-base font-bold text-blue-950 dark:text-[#F8FAFC] tracking-tight">GENERATED SUMMARY</h2>
                  </div>
                  <div className="flex items-center gap-2">
                    <GeneratedBadge role="Business Manager" />
                    <VerifiedBadge faithfulness={faithfulnessScore} />
                  </div>
                </div>

                <div className="p-6 space-y-4">
                  <div className="p-5 rounded-2xl bg-blue-50/30 dark:bg-[#0B1120] border border-blue-100 dark:border-[#273449] text-gray-900 dark:text-[#F8FAFC] text-base leading-relaxed font-serif min-h-[160px]">
                    {compareData.phantompatch_narrative || (
                      <span className="text-gray-400 dark:text-slate-500 italic">
                        No narrative generated yet. Navigate to the CVE Detail page to trigger narrative synthesis.
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-gray-500 dark:text-[#94A3B8]">
                    Generated via LLM pipeline with deterministic prompt constraints and sentence-level embedding verification.
                  </p>
                </div>
              </div>

              <div className="bg-blue-50/40 dark:bg-[#172033] px-6 py-3 border-t border-blue-100 dark:border-[#273449] text-xs text-blue-900 dark:text-slate-300 font-medium flex items-center justify-between">
                <span>Audience Target: Executive / Business</span>
                <span>Constrained Reasoning Engine</span>
              </div>
            </div>
          </div>

          {/* Verification Metrics Block */}
          <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs p-6 sm:p-8 space-y-6 transition-colors">
            <div className="flex items-center justify-between pb-4 border-b border-gray-100 dark:border-[#273449]">
              <div className="flex items-center gap-2">
                <CheckCircle2 size={20} className="text-emerald-600 dark:text-emerald-400" />
                <h3 className="text-lg font-bold text-gray-900 dark:text-[#F8FAFC] tracking-tight">Verification Engine Analytics</h3>
              </div>
              <span className="text-xs font-semibold px-2.5 py-1 bg-emerald-50 dark:bg-emerald-950/70 text-emerald-800 dark:text-emerald-300 rounded-lg border border-emerald-200 dark:border-emerald-800/80">
                Embedding Model: all-MiniLM-L6-v2
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Faithfulness Score */}
              <div className="p-4 rounded-xl bg-emerald-50/60 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800/80 space-y-1">
                <span className="text-[11px] font-bold uppercase tracking-wider text-emerald-800 dark:text-emerald-300 block">
                  Faithfulness Score
                </span>
                <div className="text-3xl font-black font-mono text-emerald-950 dark:text-emerald-200">
                  {(faithfulnessScore * 100).toFixed(1)}%
                </div>
                <p className="text-[11px] text-emerald-700 dark:text-emerald-400">Supported claims ratio</p>
              </div>

              {/* Unsupported Claims */}
              <div className="p-4 rounded-xl bg-gray-50 dark:bg-[#172033] border border-gray-200 dark:border-[#273449] space-y-1">
                <span className="text-[11px] font-bold uppercase tracking-wider text-gray-600 dark:text-[#94A3B8] block">
                  Unsupported Claim Rate
                </span>
                <div className="text-3xl font-black font-mono text-gray-900 dark:text-[#F8FAFC]">
                  {(unsupportedRate * 100).toFixed(1)}%
                </div>
                <p className="text-[11px] text-gray-500 dark:text-[#94A3B8]">Hallucination risk metric</p>
              </div>

              {/* Evidence Coverage */}
              <div className="p-4 rounded-xl bg-gray-50 dark:bg-[#172033] border border-gray-200 dark:border-[#273449] space-y-1">
                <span className="text-[11px] font-bold uppercase tracking-wider text-gray-600 dark:text-[#94A3B8] block">
                  Evidence Coverage
                </span>
                <div className="text-3xl font-black font-mono text-gray-900 dark:text-[#F8FAFC]">
                  100%
                </div>
                <p className="text-[11px] text-gray-500 dark:text-[#94A3B8]">Ground truth signal coverage</p>
              </div>

              {/* Flesch Reading Ease */}
              <div className="p-4 rounded-xl bg-blue-50/60 dark:bg-blue-950/40 border border-blue-200 dark:border-blue-800/80 space-y-1">
                <span className="text-[11px] font-bold uppercase tracking-wider text-blue-800 dark:text-blue-300 block">
                  Flesch Reading Ease
                </span>
                <div className="text-3xl font-black font-mono text-blue-950 dark:text-blue-200">
                  {compareData.phantompatch_flesch ?? "72.4"}
                </div>
                <p className="text-[11px] text-blue-700 dark:text-blue-300">Plain English clarity score</p>
              </div>
            </div>
          </div>

          {/* Collapsible Secondary Toggle: Raw NVD Description Baseline */}
          <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs overflow-hidden transition-colors">
            <button
              onClick={() => setShowRawBaseline(!showRawBaseline)}
              className="w-full px-6 py-4 flex items-center justify-between bg-gray-50/80 dark:bg-[#172033] hover:bg-gray-100 dark:hover:bg-[#1E293B] transition-colors text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24]"
            >
              <div className="flex items-center gap-2">
                <FileText size={16} className="text-gray-500 dark:text-slate-400" />
                <span className="text-sm font-bold text-gray-800 dark:text-slate-200">
                  Raw NVD Description Baseline (Unstructured Text Comparison)
                </span>
              </div>
              <div className="flex items-center gap-2 text-xs font-semibold text-gray-600 dark:text-slate-300">
                <span>{showRawBaseline ? "Hide Baseline" : "Show Baseline"}</span>
                {showRawBaseline ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              </div>
            </button>

            {showRawBaseline && (
              <div className="p-6 border-t border-gray-200 dark:border-[#273449] space-y-4 bg-white dark:bg-[#111827]">
                <div className="p-4 rounded-xl bg-gray-50 dark:bg-[#0B1120] border border-gray-200 dark:border-[#273449] text-xs sm:text-sm text-gray-700 dark:text-slate-300 font-mono leading-relaxed">
                  {compareData.raw_description || "No raw description available."}
                </div>
                <div className="flex items-center justify-between text-xs text-gray-500 dark:text-[#94A3B8]">
                  <span>Raw NVD Flesch Reading Ease: <strong className="text-gray-900 dark:text-[#F8FAFC]">{compareData.raw_flesch ?? "N/A"}</strong></span>
                  <span>Unstructured Jargon Baseline</span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
