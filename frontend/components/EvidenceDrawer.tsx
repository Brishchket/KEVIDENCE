"use client";
import React, { useEffect } from "react";
import { X, CheckCircle2, AlertTriangle, Database, ShieldCheck, FileCheck, Layers } from "lucide-react";
import { SourceDataBadge, VerifiedBadge } from "./Badges";
import { formatDate } from "@/lib/utils";

export interface EvidenceSourceItem {
  sourceName: string;
  field: string;
  value: string;
  timestamp?: string;
  reliability: string;
}

export interface ClaimEvidenceData {
  sentenceText: string;
  isSupported: boolean;
  similarityScore: number;
  matchedEvidence?: string | null;
  reason?: string;
  sources: EvidenceSourceItem[];
  cveId: string;
  audience: string;
}

interface EvidenceDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  data: ClaimEvidenceData | null;
}

export default function EvidenceDrawer({ isOpen, onClose, data }: EvidenceDrawerProps) {
  // Handle ESC key press
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen || !data) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-xs transition-opacity animate-in fade-in"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Slide-in Panel */}
      <div className="absolute inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-xl bg-white dark:bg-[#111827] shadow-2xl border-l border-gray-200 dark:border-[#273449] flex flex-col justify-between overflow-y-auto animate-in slide-in-from-right duration-200 text-gray-900 dark:text-[#F8FAFC] transition-colors">
          {/* Header */}
          <div className="p-6 border-b border-gray-200 dark:border-[#273449] bg-gray-50/80 dark:bg-[#172033] flex items-start justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-xs font-mono font-bold text-gray-500 dark:text-slate-400">{data.cveId}</span>
                <span className="text-gray-300 dark:text-slate-600">&bull;</span>
                <span className="text-xs font-semibold capitalize text-gray-600 dark:text-slate-300">{data.audience} Narrative Claim</span>
              </div>
              <h2 className="text-lg font-bold text-gray-900 dark:text-[#F8FAFC] tracking-tight flex items-center gap-2">
                <FileCheck size={20} className="text-[#ED7D24]" />
                Claim Verification & Evidence Mapping
              </h2>
            </div>
            <button
              onClick={onClose}
              className="p-2 rounded-xl text-gray-400 hover:text-gray-700 dark:hover:text-slate-200 hover:bg-gray-200/60 dark:hover:bg-[#1E293B] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24]"
              aria-label="Close drawer"
            >
              <X size={18} />
            </button>
          </div>

          {/* Content */}
          <div className="p-6 space-y-6 flex-grow">
            {/* The Specific Statement */}
            <div className="space-y-2">
              <span className="text-[11px] uppercase font-bold tracking-wider text-gray-500 dark:text-[#94A3B8]">
                Generated Narrative Claim:
              </span>
              <div className="p-4 rounded-xl bg-slate-50 dark:bg-[#0B1120] border border-slate-200 dark:border-[#273449] text-gray-900 dark:text-[#F8FAFC] text-sm font-medium leading-relaxed font-serif">
                &ldquo;{data.sentenceText}&rdquo;
              </div>
            </div>

            {/* Verification Status Card */}
            <div className={`p-4 rounded-xl border ${
              data.isSupported
                ? "bg-emerald-50/60 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800/80"
                : "bg-red-50/60 dark:bg-red-950/40 border-red-200 dark:border-red-800/80"
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  {data.isSupported ? (
                    <CheckCircle2 size={18} className="text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <AlertTriangle size={18} className="text-red-600 dark:text-red-400" />
                  )}
                  <span className={`text-sm font-bold ${data.isSupported ? "text-emerald-900 dark:text-emerald-300" : "text-red-900 dark:text-red-300"}`}>
                    {data.isSupported ? "Claim Faithfully Grounded" : "Unverified / Hallucination Risk"}
                  </span>
                </div>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-white dark:bg-[#172033] text-gray-800 dark:text-slate-200 border border-gray-200 dark:border-[#273449] shadow-2xs">
                  Cosine Similarity: {(data.similarityScore * 100).toFixed(1)}%
                </span>
              </div>

              {data.reason && (
                <p className="text-xs mt-2 text-gray-700 dark:text-slate-300 leading-relaxed font-mono">
                  {data.reason}
                </p>
              )}
            </div>

            {/* Matched Evidence Sentence */}
            {data.matchedEvidence && (
              <div className="space-y-2">
                <span className="text-[11px] uppercase font-bold tracking-wider text-gray-500 dark:text-[#94A3B8]">
                  Correlated Evidence Grounding (Embedding Model):
                </span>
                <div className="p-3.5 rounded-xl bg-gray-50 dark:bg-[#0B1120] border border-gray-200 dark:border-[#273449] text-xs text-gray-700 dark:text-slate-300 font-mono leading-relaxed">
                  {data.matchedEvidence}
                </div>
              </div>
            )}

            {/* Underlying Primary Sources */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] uppercase font-bold tracking-wider text-gray-500 dark:text-[#94A3B8]">
                  Underlying Primary Source Signals:
                </span>
                <span className="text-[11px] text-gray-400 dark:text-slate-500">Deterministic Ingestion</span>
              </div>

              <div className="space-y-2.5">
                {data.sources.map((src, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl border border-gray-200 dark:border-[#273449] bg-white dark:bg-[#172033] hover:border-gray-300 dark:hover:border-slate-600 transition-colors shadow-2xs space-y-1.5"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Database size={13} className="text-gray-500 dark:text-slate-400" />
                        <span className="text-xs font-bold text-gray-900 dark:text-[#F8FAFC]">{src.sourceName}</span>
                      </div>
                      <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-800/80">
                        {src.reliability}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-xs">
                      <span className="text-gray-500 dark:text-[#94A3B8] font-medium">{src.field}:</span>
                      <span className="font-bold text-gray-900 dark:text-[#F8FAFC] font-mono">{src.value}</span>
                    </div>

                    {src.timestamp && (
                      <div className="text-[10px] text-gray-400 dark:text-slate-500 pt-1 border-t border-gray-100 dark:border-[#273449] flex items-center justify-between">
                        <span>Synced: {formatDate(src.timestamp)}</span>
                        <span>Corpus Match</span>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="p-6 border-t border-gray-200 dark:border-[#273449] bg-gray-50/80 dark:bg-[#172033] flex items-center justify-between text-xs text-gray-500 dark:text-[#94A3B8]">
            <span>Press <kbd className="px-1.5 py-0.5 rounded bg-gray-200 dark:bg-[#1E293B] text-gray-700 dark:text-slate-300 font-mono text-[10px]">ESC</kbd> to exit</span>
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-xl bg-gray-900 hover:bg-black dark:bg-[#ED7D24] dark:hover:bg-[#D96B16] text-white font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24]"
            >
              Close Drawer
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
