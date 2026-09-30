"use client";
import { useState } from "react";
import Link from "next/link";
import { Shield, Settings, Bell, Search, Table2 } from "lucide-react";

const TABS = ["Data Overview", "Priority Alerts", "Risk Narratives", "Pipeline Runs"];

export default function Navbar() {
  const [active, setActive] = useState("Data Overview");

  return (
    <nav
      className="sticky top-0 z-40 flex items-center justify-between px-5 py-3"
      style={{ background: "var(--bg-page)", borderBottom: "1px solid #BDC1AE" }}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 min-w-[160px]">
        <Shield size={22} className="text-[#ED7D24]" strokeWidth={2.2} />
        <span className="font-bold text-[15px] tracking-tight text-[#1C2B27]">
          Phantom<span className="text-[#ED7D24]">Patch</span>
        </span>
      </div>

      {/* Tabs */}
      <div className="hidden md:flex items-center gap-1 bg-[#C5C9B7] rounded-xl px-1.5 py-1.5">
        <Link
          href="/"
          className={`px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-colors duration-150 ${
            active === "Dashboard" ? "bg-white text-[#1C2B27] shadow-sm" : "text-[#5A6B62] hover:text-[#1C2B27]"
          }`}
          onClick={() => setActive("Dashboard")}
        >
          Dashboard
        </Link>
        <Link
          href="/compare"
          className={`px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-colors duration-150 ${
            active === "Compare" ? "bg-white text-[#1C2B27] shadow-sm" : "text-[#5A6B62] hover:text-[#1C2B27]"
          }`}
          onClick={() => setActive("Compare")}
        >
          Compare
        </Link>
        <Link
          href="/evaluation"
          className={`px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-colors duration-150 ${
            active === "Evaluation" ? "bg-white text-[#1C2B27] shadow-sm" : "text-[#5A6B62] hover:text-[#1C2B27]"
          }`}
          onClick={() => setActive("Evaluation")}
        >
          Evaluation
        </Link>
        <Link
          href="/survey"
          className={`px-3.5 py-1.5 rounded-lg text-[13px] font-medium transition-colors duration-150 ${
            active === "Survey" ? "bg-white text-[#1C2B27] shadow-sm" : "text-[#5A6B62] hover:text-[#1C2B27]"
          }`}
          onClick={() => setActive("Survey")}
        >
          Survey
        </Link>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-2 min-w-[160px] justify-end">
        <Link
          href="/"
          className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[13px] font-medium border border-[#BDC1AE] bg-white/60 text-[#1C2B27] hover:bg-white transition-colors"
          aria-label="CVE Table"
        >
          <Table2 size={14} />
          CVE Table
        </Link>
        <button onClick={() => alert("Settings coming soon!")} className="p-2 rounded-lg text-[#5A6B62] hover:bg-[#C5C9B7] transition-colors" aria-label="Settings">
          <Settings size={16} />
        </button>
        <button onClick={() => alert("Notifications coming soon!")} className="p-2 rounded-lg text-[#5A6B62] hover:bg-[#C5C9B7] transition-colors" aria-label="Notifications">
          <Bell size={16} />
        </button>
        <button onClick={() => alert("Search coming soon!")} className="p-2 rounded-lg text-[#5A6B62] hover:bg-[#C5C9B7] transition-colors" aria-label="Search">
          <Search size={16} />
        </button>
      </div>
    </nav>
  );
}
