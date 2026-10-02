import React from "react";
import { Database, Sparkles, CheckCircle2, ShieldAlert, ShieldCheck, AlertTriangle, Info } from "lucide-react";

export function PriorityBadge({ label, size = "md" }: { label?: string; size?: "sm" | "md" | "lg" }) {
  const norm = (label || "LOW").toUpperCase();
  
  const sizeClasses = {
    sm: "px-2 py-0.5 text-xs font-semibold",
    md: "px-2.5 py-1 text-xs font-bold tracking-wide",
    lg: "px-3.5 py-1.5 text-sm font-bold tracking-wider",
  }[size];

  const colorClasses = {
    CRITICAL: "bg-red-50 text-red-700 border border-red-200 ring-1 ring-red-300/40 dark:bg-red-950/60 dark:text-red-300 dark:border-red-800/80 dark:ring-red-700/30",
    HIGH: "bg-orange-50 text-orange-700 border border-orange-200 ring-1 ring-orange-300/40 dark:bg-orange-950/60 dark:text-orange-300 dark:border-orange-800/80 dark:ring-orange-700/30",
    MEDIUM: "bg-amber-50 text-amber-700 border border-amber-200 ring-1 ring-amber-300/40 dark:bg-amber-950/60 dark:text-amber-300 dark:border-amber-800/80 dark:ring-amber-700/30",
    LOW: "bg-emerald-50 text-emerald-700 border border-emerald-200 ring-1 ring-emerald-300/40 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800/80 dark:ring-emerald-700/30",
  }[norm] || "bg-gray-50 text-gray-700 border border-gray-200 dark:bg-[#172033] dark:text-slate-300 dark:border-[#273449]";

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-md uppercase transition-colors ${sizeClasses} ${colorClasses}`}>
      {norm === "CRITICAL" && <ShieldAlert size={size === "lg" ? 16 : 13} className="text-red-600 dark:text-red-400" />}
      {norm === "HIGH" && <AlertTriangle size={size === "lg" ? 16 : 13} className="text-orange-600 dark:text-orange-400" />}
      {norm === "MEDIUM" && <Info size={size === "lg" ? 16 : 13} className="text-amber-600 dark:text-amber-400" />}
      {norm === "LOW" && <ShieldCheck size={size === "lg" ? 16 : 13} className="text-emerald-600 dark:text-emerald-400" />}
      {norm} PRIORITY
    </span>
  );
}

export function SourceDataBadge({ source }: { source?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold uppercase tracking-wider bg-slate-100 text-slate-700 border border-slate-300/80 dark:bg-[#172033] dark:text-slate-300 dark:border-[#273449] shadow-2xs transition-colors">
      <Database size={12} className="text-slate-500 dark:text-slate-400" />
      SOURCE DATA {source ? `• ${source}` : ""}
    </span>
  );
}

export function GeneratedBadge({ role }: { role?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold uppercase tracking-wider bg-indigo-50 text-indigo-700 border border-indigo-200 dark:bg-indigo-950/60 dark:text-indigo-300 dark:border-indigo-800 shadow-2xs transition-colors">
      <Sparkles size={12} className="text-indigo-500 dark:text-indigo-400" />
      GENERATED {role ? `• ${role}` : ""}
    </span>
  );
}

export function VerifiedBadge({ faithfulness, confidence }: { faithfulness?: number; confidence?: string }) {
  const percent = faithfulness !== undefined && faithfulness !== null 
    ? Math.round(faithfulness > 1 ? faithfulness : faithfulness * 100)
    : null;

  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-bold uppercase tracking-wider bg-emerald-50 text-emerald-800 border border-emerald-300/90 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800 shadow-2xs transition-colors">
      <CheckCircle2 size={12} className="text-emerald-600 dark:text-emerald-400" />
      VERIFIED {percent !== null ? `(Faithfulness: ${percent}%)` : (confidence ? `• ${confidence}` : "")}
    </span>
  );
}
