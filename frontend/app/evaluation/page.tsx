"use client";
import React, { useState, useEffect } from "react";
import { fetcher } from "@/lib/api";
import { SourceDataBadge, VerifiedBadge } from "@/components/Badges";
import { Activity, CheckCircle2, AlertTriangle, ShieldCheck, Terminal, Award, FileCode2 } from "lucide-react";

export default function EvaluationPage() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetcher("/evaluation/summary").then((d) => {
      setData(d);
      setLoading(false);
    });
  }, []);

  if (loading) {
    return (
      <div className="p-16 text-center text-gray-500 dark:text-[#94A3B8] bg-white dark:bg-[#111827] rounded-2xl border border-gray-200 dark:border-[#273449] max-w-[1600px] mx-auto w-full">
        <div className="w-8 h-8 border-2 border-[#ED7D24] border-t-transparent rounded-full animate-spin mx-auto mb-3" />
        <span className="text-sm font-medium">Loading evaluation harness analytics...</span>
      </div>
    );
  }

  return (
    <div className="max-w-[1600px] mx-auto space-y-8 w-full transition-colors duration-150">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-2 border-b border-gray-200/80 dark:border-[#273449]">
        <div>
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300 text-xs font-bold tracking-wide uppercase mb-2">
            Quantitative Research Harness
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold text-gray-950 dark:text-[#F8FAFC] tracking-tight">
            KEVIDENCE — Evaluation Suite Results
          </h1>
          <p className="text-sm sm:text-base text-gray-600 dark:text-[#94A3B8] mt-1 max-w-3xl">
            Automated verification results for baseline comparisons, priority calibration, verifier accuracy, and blinded survey evaluation.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <VerifiedBadge confidence="Automated Validation Suite" />
        </div>
      </div>

      {/* Results Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {data &&
          Object.entries(data).map(([key, result]: [string, any]) => (
            <div
              key={key}
              className="bg-white dark:bg-[#111827] rounded-2xl border border-gray-200/90 dark:border-[#273449] shadow-2xs overflow-hidden flex flex-col justify-between transition-colors"
            >
              <div className="bg-gray-50/80 dark:bg-[#172033] px-6 py-4 border-b border-gray-200 dark:border-[#273449] flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <Activity size={18} className="text-[#ED7D24]" />
                  <h2 className="text-base font-bold text-gray-900 dark:text-[#F8FAFC] capitalize tracking-tight">
                    {key.replace(/_/g, " ")}
                  </h2>
                </div>

                {result.pass_fail && (
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(result.pass_fail).map(([metric, status]: [string, any]) => {
                      const s = String(status);
                      const isPass = s.includes("PASS");
                      const isPending = s.includes("PENDING");
                      return (
                        <span
                          key={metric}
                          className={`px-2.5 py-0.5 text-xs font-bold font-mono rounded-md border ${
                            isPass
                              ? "bg-emerald-50 dark:bg-emerald-950/70 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800/80"
                              : isPending
                              ? "bg-amber-50 dark:bg-amber-950/70 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-800/80"
                              : "bg-red-50 dark:bg-red-950/70 text-red-800 dark:text-red-300 border-red-300 dark:border-red-800/80"
                          }`}
                        >
                          {metric}: {s}
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="p-6">
                {result.status ? (
                  <div className="p-4 rounded-xl bg-gray-50 dark:bg-[#0B1120] text-gray-600 dark:text-slate-300 text-xs italic border dark:border-[#273449]">
                    {result.status} {result.note ? `— ${result.note}` : ""}
                  </div>
                ) : (
                  <pre className="text-xs bg-slate-900 dark:bg-[#0B1120] text-slate-100 p-4 rounded-xl overflow-x-auto font-mono leading-relaxed border border-slate-800 dark:border-[#273449]">
                    {JSON.stringify(result, null, 2)}
                  </pre>
                )}
              </div>

              <div className="px-6 py-3 bg-gray-50/50 dark:bg-[#172033] border-t border-gray-100 dark:border-[#273449] text-[11px] text-gray-500 dark:text-[#94A3B8] flex items-center justify-between">
                <span>Evaluation Output</span>
                <span>Deterministic Harness</span>
              </div>
            </div>
          ))}
      </div>
    </div>
  );
}
