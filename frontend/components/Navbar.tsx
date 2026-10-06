"use client";
import React, { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Shield, FileText, Sun, Moon } from "lucide-react";
import { APP_NAME, APP_DESCRIPTOR } from "@/lib/constants";
import { useTheme } from "./ThemeProvider";
import LiveIndicator from "./LiveIndicator";
import { useLiveFeedContext } from "./LiveFeedContext";
import { useSyncStatus } from "@/lib/useSyncStatus";

export default function Navbar() {
  const pathname = usePathname();
  const { theme, toggleTheme } = useTheme();
  const [currentHash, setCurrentHash] = useState("");

  // Use shared live feed context (single SSE connection for the app)
  const { connectionState } = useLiveFeedContext();
  const syncStatus = useSyncStatus(30_000);

  useEffect(() => {
    // Sync hash on mount and on hashchange
    const updateHash = () => {
      if (typeof window !== "undefined") {
        setCurrentHash(window.location.hash);
      }
    };
    updateHash();
    window.addEventListener("hashchange", updateHash);
    return () => window.removeEventListener("hashchange", updateHash);
  }, []);

  // Update hash when pathname changes if not containing hash
  useEffect(() => {
    if (typeof window !== "undefined") {
      setCurrentHash(window.location.hash);
    }
  }, [pathname]);

  const isDark = theme === "dark";

  // Derive active route state purely from current route & hash
  const isDashboard = pathname === "/" && currentHash !== "#explorer";
  const isExplorer = (pathname === "/" && currentHash === "#explorer") || pathname.startsWith("/cve/");
  const isCompare = pathname.startsWith("/compare");
  const isEvaluation = pathname.startsWith("/evaluation");
  const isSurvey = pathname.startsWith("/survey");

  const getItemClass = (isActive: boolean) => {
    if (isActive) {
      return isDark
        ? "bg-[#1E293B] text-[#F8FAFC] border-[#334155] shadow-2xs font-bold"
        : "bg-white text-gray-950 border-gray-200/90 shadow-2xs font-bold";
    }
    return isDark
      ? "text-[#94A3B8] hover:text-[#F8FAFC] hover:bg-[#1E293B]/60 border-transparent font-semibold"
      : "text-gray-600 hover:text-gray-900 hover:bg-white/70 border-transparent font-semibold";
  };

  return (
    <header className="sticky top-0 z-40 bg-white/95 dark:bg-[#111827]/95 backdrop-blur-md border-b border-gray-200 dark:border-[#273449] shadow-2xs transition-colors duration-150">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Logo & Descriptor */}
          <Link
            href="/"
            onClick={() => setCurrentHash("")}
            className="flex items-center gap-3 group focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] rounded-xl p-1"
          >
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-[#ED7D24] to-[#F59E0B] flex items-center justify-center text-white shadow-sm ring-2 ring-orange-200/50 dark:ring-orange-500/20 group-hover:scale-105 transition-transform duration-200">
              <Shield size={22} className="stroke-[2.2]" />
            </div>
            <div className="flex flex-col">
              <span className="font-extrabold text-lg tracking-tight text-gray-900 dark:text-[#F8FAFC] leading-tight">
                K<span className="text-[#ED7D24]">EVIDENCE</span>
              </span>
              <span className="text-[11px] font-medium text-gray-500 dark:text-[#94A3B8] tracking-normal hidden sm:block">
                {APP_DESCRIPTOR}
              </span>
            </div>
          </Link>

          {/* Primary Navigation Bar */}
          <nav
            aria-label="Main Navigation"
            className="flex items-center gap-1 bg-gray-100/90 dark:bg-[#0B1120] p-1 rounded-xl border border-gray-200/80 dark:border-[#273449] transition-colors"
          >
            <Link
              href="/"
              onClick={() => setCurrentHash("")}
              className={`px-3.5 py-1.5 rounded-lg text-xs sm:text-sm border transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${getItemClass(
                isDashboard
              )}`}
              aria-current={isDashboard ? "page" : undefined}
            >
              Dashboard
            </Link>

            <Link
              href="/#explorer"
              onClick={() => setCurrentHash("#explorer")}
              className={`px-3.5 py-1.5 rounded-lg text-xs sm:text-sm border transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${getItemClass(
                isExplorer
              )}`}
              aria-current={isExplorer ? "page" : undefined}
            >
              CVE Explorer
            </Link>

            <Link
              href="/compare"
              onClick={() => setCurrentHash("")}
              className={`px-3.5 py-1.5 rounded-lg text-xs sm:text-sm border transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${getItemClass(
                isCompare
              )}`}
              aria-current={isCompare ? "page" : undefined}
            >
              Compare
            </Link>

            <Link
              href="/evaluation"
              onClick={() => setCurrentHash("")}
              className={`px-3.5 py-1.5 rounded-lg text-xs sm:text-sm border transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${getItemClass(
                isEvaluation
              )}`}
              aria-current={isEvaluation ? "page" : undefined}
            >
              Evaluation
            </Link>
          </nav>

          {/* Right Actions: LIVE indicator, Research Survey & Global Theme Toggle */}
          <div className="flex items-center gap-3">
            {/* LIVE / Sync Status Indicator */}
            <LiveIndicator connectionState={connectionState} syncStatus={syncStatus} />
            {/* Global Light / Dark Theme Toggle */}
            <button
              type="button"
              onClick={toggleTheme}
              aria-label={isDark ? "Switch to light theme" : "Switch to dark theme"}
              title={isDark ? "Switch to light theme" : "Switch to dark theme"}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold border transition-all shadow-2xs focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${
                isDark
                  ? "bg-[#172033] hover:bg-[#1E293B] text-amber-300 border-[#273449]"
                  : "bg-white hover:bg-gray-50 text-gray-700 border-gray-200"
              }`}
            >
              {isDark ? (
                <>
                  <Sun size={15} className="text-amber-400" />
                  <span className="text-[#F8FAFC]">Light</span>
                </>
              ) : (
                <>
                  <Moon size={15} className="text-slate-600" />
                  <span className="text-gray-700">Dark</span>
                </>
              )}
            </button>

            {/* Research Survey Link */}
            <Link
              href="/survey"
              onClick={() => setCurrentHash("")}
              className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium border transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-[#ED7D24] ${
                isSurvey
                  ? isDark
                    ? "bg-purple-950/60 border-purple-700 text-purple-200 ring-1 ring-purple-600"
                    : "bg-purple-50 border-purple-300 text-purple-800 ring-1 ring-purple-400"
                  : isDark
                  ? "bg-[#172033] border-[#273449] text-[#94A3B8] hover:bg-purple-950/40 hover:text-purple-300 hover:border-purple-800/60"
                  : "bg-gray-50 border-gray-200 text-gray-600 hover:bg-purple-50/50 hover:text-purple-700 hover:border-purple-200"
              }`}
              title="Blinded Narrative Evaluation Survey (Research Only)"
            >
              <FileText size={13} className={isDark ? "text-purple-400" : "text-purple-600"} />
              <span className="font-semibold">Survey</span>
              <span
                className={`text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.2 rounded ${
                  isDark ? "bg-purple-900/80 text-purple-200" : "bg-purple-100 text-purple-700"
                }`}
              >
                Research
              </span>
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}
