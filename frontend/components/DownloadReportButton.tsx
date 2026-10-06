"use client";
/**
 * DownloadReportButton.tsx — Client component for downloading the PDF vulnerability report.
 *
 * Supports:
 *   - "button" variant: Primary button on the CVE detail page with icon, spinner, and error state
 *   - "icon" variant: Compact icon action button in CVETable rows
 *
 * Filename: kevidence-CVE-XXXX-YYYY.pdf
 */

import React, { useState } from "react";
import { Download, Loader2, AlertCircle, FileText } from "lucide-react";
import { API_BASE } from "@/lib/api";

interface DownloadReportButtonProps {
  cveId: string;
  variant?: "button" | "icon";
  className?: string;
}

export default function DownloadReportButton({
  cveId,
  variant = "button",
  className = "",
}: DownloadReportButtonProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDownload = async (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();

    if (loading) return;
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE}/cves/${cveId}/report.pdf`);
      if (!response.ok) {
        throw new Error(`Server returned ${response.status}`);
      }

      const blob = await response.blob();
      const blobUrl = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = blobUrl;
      link.download = `kevidence-${cveId}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(blobUrl);
    } catch (err: any) {
      console.error("PDF download failed:", err);
      setError("Download failed");
      setTimeout(() => setError(null), 4000);
    } finally {
      setLoading(false);
    }
  };

  if (variant === "icon") {
    return (
      <button
        type="button"
        onClick={handleDownload}
        disabled={loading}
        title={error || `Download PDF Advisory Report for ${cveId}`}
        aria-label={`Download PDF Advisory Report for ${cveId}`}
        className={`p-1.5 rounded-lg border text-xs transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${
          error
            ? "border-red-300 bg-red-50 text-red-600 dark:border-red-800 dark:bg-red-950 dark:text-red-400"
            : "border-gray-200 bg-white text-gray-700 hover:bg-gray-50 hover:text-gray-900 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 dark:hover:text-white"
        } ${className}`}
      >
        {loading ? (
          <Loader2 size={13} className="animate-spin text-[#ED7D24]" />
        ) : error ? (
          <AlertCircle size={13} className="text-red-500" />
        ) : (
          <FileText size={13} />
        )}
      </button>
    );
  }

  return (
    <div className="relative inline-flex flex-col items-start">
      <button
        type="button"
        onClick={handleDownload}
        disabled={loading}
        className={`inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs sm:text-sm font-bold shadow-2xs transition-all focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${
          loading
            ? "bg-gray-100 text-gray-400 border border-gray-200 dark:bg-slate-800 dark:text-slate-500 dark:border-slate-700 cursor-not-allowed"
            : error
            ? "bg-red-50 text-red-700 border border-red-200 dark:bg-red-950 dark:text-red-300 dark:border-red-800"
            : "bg-white hover:bg-gray-50 text-gray-900 border border-gray-200 dark:bg-[#172033] dark:hover:bg-[#1E293B] dark:text-[#F8FAFC] dark:border-[#273449]"
        } ${className}`}
      >
        {loading ? (
          <>
            <Loader2 size={16} className="animate-spin text-[#ED7D24]" />
            <span>Compiling Advisory PDF…</span>
          </>
        ) : error ? (
          <>
            <AlertCircle size={16} className="text-red-500" />
            <span>{error} — Retry</span>
          </>
        ) : (
          <>
            <Download size={16} className="text-[#ED7D24]" />
            <span>Download PDF Report</span>
          </>
        )}
      </button>
    </div>
  );
}
