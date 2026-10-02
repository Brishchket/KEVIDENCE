"use client";
import React, { useState } from "react";
import { ChevronDown, ChevronUp, Calculator, ShieldCheck, Flame, TrendingUp, AlertTriangle, Building2, Server } from "lucide-react";
import { SCORING_WEIGHTS, ORG_CONTEXT } from "@/lib/constants";

interface ScoreCalculationAccordionProps {
  evidence: any;
}

export default function ScoreCalculationAccordion({ evidence }: ScoreCalculationAccordionProps) {
  const [isOpen, setIsOpen] = useState(false);

  const cvssScore = Number(evidence?.cvss?.score || 0);
  const cvssNorm = Math.min(1.0, cvssScore / 10.0);
  const epssProb = Number(evidence?.epss?.probability || 0);
  const inKev = Boolean(evidence?.kev?.in_kev);
  const priorityScore = Number(evidence?.priority?.score || 0);
  const priorityLabel = evidence?.priority?.label || "LOW";

  // Real breakdown terms from evidence
  const breakdown = evidence?.priority?.breakdown || {};
  const cvssContrib = breakdown.cvss_contribution !== undefined ? breakdown.cvss_contribution : (cvssNorm * SCORING_WEIGHTS.cvss.weight);
  const epssContrib = breakdown.epss_contribution !== undefined ? breakdown.epss_contribution : (epssProb * SCORING_WEIGHTS.epss.weight);
  const kevContrib = breakdown.kev_contribution !== undefined ? breakdown.kev_contribution : ((inKev ? 1.0 : 0.0) * SCORING_WEIGHTS.kev.weight);

  // Level labels for "Why is this prioritized?" progress bars
  const techSeverityLabel = cvssScore >= 9.0 ? "CRITICAL" : cvssScore >= 7.0 ? "HIGH" : cvssScore >= 4.0 ? "MEDIUM" : "LOW";
  const exploitLikelihoodLabel = epssProb >= 0.5 ? "HIGH" : epssProb >= 0.05 ? "MODERATE" : "LOW";
  const knownExploitLabel = inKev ? "CONFIRMED (KEV)" : "NOT OBSERVED";
  const orgRelevanceLabel = ORG_CONTEXT.relevanceByPriority[priorityLabel] || "MEDIUM";

  const orgRelevancePercent = orgRelevanceLabel === "HIGH" ? 90 : orgRelevanceLabel === "MEDIUM" ? 50 : 25;

  return (
    <div className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs p-6 space-y-6 transition-colors">
      {/* 1. Why is this prioritized? (Signal Breakdown Bars) */}
      <div>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-base font-bold text-gray-900 dark:text-[#F8FAFC] tracking-tight">Why is this prioritized?</h3>
            <p className="text-xs text-gray-500 dark:text-[#94A3B8] mt-0.5">Multidimensional risk factors across technical and operational domains</p>
          </div>
        </div>

        <div className="space-y-4">
          {/* Technical Severity */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-700 dark:text-slate-300">
              <span className="flex items-center gap-1.5">
                <AlertTriangle size={14} className="text-orange-600 dark:text-orange-400" />
                Technical Severity (CVSS v3.1)
              </span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-gray-900 dark:text-[#F8FAFC]">{cvssScore.toFixed(1)} / 10.0</span>
                <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-orange-100 text-orange-800 dark:bg-orange-950/70 dark:text-orange-300 border dark:border-orange-800/60">
                  {techSeverityLabel}
                </span>
              </div>
            </div>
            <div className="w-full bg-gray-100 dark:bg-[#172033] rounded-full h-2 overflow-hidden">
              <div
                className="h-full bg-orange-500 rounded-full transition-all duration-300"
                style={{ width: `${cvssNorm * 100}%` }}
              />
            </div>
          </div>

          {/* Exploitation Likelihood */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-700 dark:text-slate-300">
              <span className="flex items-center gap-1.5">
                <TrendingUp size={14} className="text-amber-600 dark:text-amber-400" />
                Exploitation Likelihood (EPSS)
              </span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-gray-900 dark:text-[#F8FAFC]">{(epssProb * 100).toFixed(2)}%</span>
                <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300 border dark:border-amber-800/60">
                  {exploitLikelihoodLabel}
                </span>
              </div>
            </div>
            <div className="w-full bg-gray-100 dark:bg-[#172033] rounded-full h-2 overflow-hidden">
              <div
                className="h-full bg-amber-500 rounded-full transition-all duration-300"
                style={{ width: `${Math.max(epssProb * 100, epssProb > 0 ? 5 : 0)}%` }}
              />
            </div>
          </div>

          {/* Known Exploitation */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-700 dark:text-slate-300">
              <span className="flex items-center gap-1.5">
                <Flame size={14} className="text-red-600 dark:text-red-400" />
                Known Exploitation (CISA KEV)
              </span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-gray-900 dark:text-[#F8FAFC]">{inKev ? "Catalog Match" : "None"}</span>
                <span className={`text-[10px] font-bold px-1.5 py-0.2 rounded border ${
                  inKev
                    ? "bg-red-100 text-red-800 dark:bg-red-950/70 dark:text-red-300 dark:border-red-800/60"
                    : "bg-gray-100 text-gray-600 dark:bg-[#172033] dark:text-slate-400 dark:border-[#273449]"
                }`}>
                  {knownExploitLabel}
                </span>
              </div>
            </div>
            <div className="w-full bg-gray-100 dark:bg-[#172033] rounded-full h-2 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-300 ${inKev ? "bg-red-600" : "bg-gray-300 dark:bg-slate-700"}`}
                style={{ width: inKev ? "100%" : "0%" }}
              />
            </div>
          </div>

          {/* Organizational Relevance */}
          <div className="space-y-1.5">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-700 dark:text-slate-300">
              <span className="flex items-center gap-1.5">
                <Building2 size={14} className="text-purple-600 dark:text-purple-400" />
                Organizational Relevance
              </span>
              <div className="flex items-center gap-2">
                <span className="font-mono text-gray-900 dark:text-[#F8FAFC]">{ORG_CONTEXT.industry.split('&')[0].trim()}</span>
                <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-purple-100 text-purple-800 dark:bg-purple-950/70 dark:text-purple-300 border dark:border-purple-800/60">
                  {orgRelevanceLabel}
                </span>
              </div>
            </div>
            <div className="w-full bg-gray-100 dark:bg-[#172033] rounded-full h-2 overflow-hidden">
              <div
                className="h-full bg-purple-600 rounded-full transition-all duration-300"
                style={{ width: `${orgRelevancePercent}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* 2. How is this calculated? (Expandable Accordion) */}
      <div className="pt-4 border-t border-gray-100 dark:border-[#273449]">
        <button
          onClick={() => setIsOpen(!isOpen)}
          className="w-full flex items-center justify-between p-3.5 rounded-xl bg-gray-50/90 hover:bg-gray-100 dark:bg-[#172033] dark:hover:bg-[#1E293B] text-xs font-bold text-gray-800 dark:text-slate-200 transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24]"
        >
          <span className="flex items-center gap-2">
            <Calculator size={16} className="text-[#ED7D24]" />
            How is this calculated? (Mathematical Scoring Model)
          </span>
          {isOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
        </button>

        {isOpen && (
          <div className="mt-4 p-5 rounded-2xl bg-slate-900 dark:bg-[#0B1120] text-slate-100 text-xs space-y-4 font-mono shadow-inner border border-slate-800 dark:border-[#273449]">
            <div className="text-slate-400 text-[11px] pb-2 border-b border-slate-800 dark:border-[#273449]">
              priority_score = (W_cvss * (cvss / 10)) + (W_epss * epss) + (W_kev * in_kev)
            </div>

            <div className="space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-slate-300">
                  &bull; {SCORING_WEIGHTS.cvss.label} ({SCORING_WEIGHTS.cvss.percentage}):
                </span>
                <span className="text-emerald-400 font-bold">
                  0.30 &times; {cvssNorm.toFixed(3)} = +{Number(cvssContrib).toFixed(3)}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-300">
                  &bull; {SCORING_WEIGHTS.epss.label} ({SCORING_WEIGHTS.epss.percentage}):
                </span>
                <span className="text-emerald-400 font-bold">
                  0.30 &times; {epssProb.toFixed(3)} = +{Number(epssContrib).toFixed(3)}
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-slate-300">
                  &bull; {SCORING_WEIGHTS.kev.label} ({SCORING_WEIGHTS.kev.percentage}):
                </span>
                <span className="text-emerald-400 font-bold">
                  0.40 &times; {inKev ? "1.000" : "0.000"} = +{Number(kevContrib).toFixed(3)}
                </span>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 dark:border-[#273449] flex items-center justify-between text-sm">
              <span className="font-bold text-white uppercase tracking-wider">Final Composite Score:</span>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-[#ED7D24] text-base">{priorityScore.toFixed(3)}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-white border border-slate-700">
                  &rarr; {priorityLabel}
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
